"""A small in-process DNS server for tests: UDP, TCP, DNS-over-TLS and DNS-over-HTTPS.

Rules map names to behaviours (answer, NXDOMAIN, drop, ...). A rule registered for
``*.example.com`` also answers every subdomain of ``example.com``.
"""

import socket
import socketserver
import ssl
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

Rule = Callable[[dns.message.Message, str], dns.message.Message | None]

SOA_RDATA = "ns1.upstream.test. hostmaster.upstream.test. 1 7200 3600 1209600 300"


def _response(query: dns.message.Message, ede: tuple[int, str] | None = None):
    response = dns.message.make_response(query)
    if ede is not None:
        response.use_edns(0, payload=1232, options=[dns.edns.EDEOption(ede[0], ede[1])])
    return response


def answer(*addresses: str, ede: tuple[int, str] | None = None) -> Rule:
    """Answer A/AAAA queries with the addresses of the matching family (NODATA otherwise)."""

    def rule(query, transport):
        response = _response(query, ede)
        question = query.question[0]
        wanted = "A" if question.rdtype == dns.rdatatype.A else "AAAA"
        family = [a for a in addresses if (":" in a) == (wanted == "AAAA")]
        if family:
            response.answer.append(dns.rrset.from_text(question.name, 300, "IN", wanted, *family))
        return response

    return rule


def cname(target: str, *addresses: str) -> Rule:
    def rule(query, transport):
        response = _response(query)
        question = query.question[0]
        target_name = dns.name.from_text(target)
        response.answer.append(
            dns.rrset.from_text(question.name, 300, "IN", "CNAME", target_name.to_text())
        )
        v4 = [a for a in addresses if ":" not in a]
        if v4 and question.rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(target_name, 300, "IN", "A", *v4))
        return response

    return rule


def nxdomain(soa_owner: str | None = None, ede: tuple[int, str] | None = None) -> Rule:
    """NXDOMAIN, optionally with an SOA in the authority section like a real upstream answer."""

    def rule(query, transport):
        response = _response(query, ede)
        response.set_rcode(dns.rcode.NXDOMAIN)
        if soa_owner is not None:
            owner = dns.name.from_text(soa_owner)
            response.authority.append(dns.rrset.from_text(owner, 300, "IN", "SOA", SOA_RDATA))
        return response

    return rule


def rcode(code: int, ede: tuple[int, str] | None = None) -> Rule:
    def rule(query, transport):
        response = _response(query, ede)
        response.set_rcode(code)
        return response

    return rule


def nodata() -> Rule:
    return lambda query, transport: _response(query)


def drop() -> Rule:
    return lambda query, transport: None


HANGUP = object()


def hangup() -> Rule:
    """Close a TCP/TLS connection without answering (a UDP query is just dropped)."""
    return lambda query, transport: HANGUP


def truncated_over_udp(inner: Rule) -> Rule:
    """Send an empty, truncated (TC) answer over UDP and the real answer over TCP."""

    def rule(query, transport):
        if transport == "udp":
            response = _response(query)
            response.flags |= dns.flags.TC
            return response
        return inner(query, transport)

    return rule


def _recv_exact(conn, size: int) -> bytes | None:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


class FakeDNSServer:
    def __init__(self, default: Rule | None = None) -> None:
        self.rules: dict[str, Rule] = {}
        self.default = default or nxdomain(soa_owner="test.")
        self.queries: list[tuple[str, str]] = []  # (transport, qname)
        self.connections: dict[str, int] = {"tcp": 0, "tls": 0, "https": 0}
        self.port = 0
        self.tls_port = 0
        self.doh_port = 0
        self._servers: list[socketserver.BaseServer] = []
        self._lock = threading.Lock()

    # -- rules ---------------------------------------------------------------------------------

    def set(self, name: str, rule: Rule) -> None:
        self.rules[name.lower().rstrip(".")] = rule

    def lookup(self, qname: dns.name.Name) -> Rule:
        name = qname.to_text(omit_final_dot=True).lower()
        if name in self.rules:
            return self.rules[name]
        labels = name.split(".")
        for i in range(1, len(labels)):
            wildcard = "*." + ".".join(labels[i:])
            if wildcard in self.rules:
                return self.rules[wildcard]
        return self.default

    def reply(self, wire: bytes, transport: str) -> bytes | None:
        query = dns.message.from_wire(wire)
        qname = query.question[0].name
        with self._lock:
            self.queries.append((transport, qname.to_text(omit_final_dot=True)))
        response = self.lookup(qname)(query, transport)
        if response is None or response is HANGUP:
            return response
        return response.to_wire()

    def _count(self, kind: str) -> None:
        with self._lock:
            self.connections[kind] += 1

    # -- servers -------------------------------------------------------------------------------

    def start(self) -> "FakeDNSServer":
        """Serve UDP and TCP on the same 127.0.0.1 port."""
        for _ in range(50):
            udp = _UDPServer(("127.0.0.1", 0), _UDPHandler, self)
            try:
                tcp = _TCPServer(("127.0.0.1", udp.server_address[1]), _TCPHandler, self, None)
            except OSError:
                udp.server_close()
                continue
            self.port = udp.server_address[1]
            self._serve(udp)
            self._serve(tcp)
            return self
        raise RuntimeError("could not bind UDP and TCP to the same port")

    def start_tls(self, context: ssl.SSLContext) -> int:
        server = _TCPServer(("127.0.0.1", 0), _TCPHandler, self, context)
        self.tls_port = server.server_address[1]
        self._serve(server)
        return self.tls_port

    def start_doh(self, context: ssl.SSLContext, path: str = "/dns-query") -> int:
        server = _DoHServer(("127.0.0.1", 0), _DoHHandler)
        server.owner, server.tls_context, server.path = self, context, path
        self.doh_port = server.server_address[1]
        self._serve(server)
        return self.doh_port

    def _serve(self, server: socketserver.BaseServer) -> None:
        self._servers.append(server)
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def stop(self) -> None:
        for server in self._servers:
            server.shutdown()
            server.server_close()
        self._servers.clear()


class _UDPServer(socketserver.ThreadingUDPServer):
    daemon_threads = True

    def __init__(self, address, handler, owner: FakeDNSServer) -> None:
        self.owner = owner
        super().__init__(address, handler)


class _TCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, owner: FakeDNSServer, tls: ssl.SSLContext | None) -> None:
        self.owner = owner
        self.tls_context = tls
        super().__init__(address, handler)

    def handle_error(self, request, client_address) -> None:  # TLS handshakes failing is expected
        pass


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        reply = self.server.owner.reply(data, "udp")
        if isinstance(reply, bytes):
            sock.sendto(reply, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        owner: FakeDNSServer = self.server.owner
        conn = self.request
        transport = "tcp"
        if self.server.tls_context is not None:
            conn = self.server.tls_context.wrap_socket(conn, server_side=True)
            transport = "tls"
        owner._count(transport)
        try:
            while True:
                header = _recv_exact(conn, 2)
                if header is None:
                    return
                data = _recv_exact(conn, int.from_bytes(header, "big"))
                if data is None:
                    return
                reply = owner.reply(data, transport)
                if reply is HANGUP:
                    return
                if reply is None:
                    conn.recv(1)  # "drop": stay silent until the client gives up
                    return
                conn.sendall(len(reply).to_bytes(2, "big") + reply)
        except OSError:
            return


class _DoHServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:
        pass


class _DoHHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, so connection reuse can be observed

    def setup(self) -> None:
        self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
        self.server.owner._count("https")
        super().setup()

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path != self.server.path:
            self._send(404, b"not found", "text/plain")
            return
        if self.headers.get("Content-Type") != "application/dns-message":
            self._send(415, b"unsupported media type", "text/plain")
            return
        reply = self.server.owner.reply(body, "https")
        if not isinstance(reply, bytes):
            self._send(504, b"", "text/plain")
            return
        self._send(200, reply, "application/dns-message")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def free_port() -> int:
    """A local port with nothing listening on it (for unreachable-resolver tests)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
