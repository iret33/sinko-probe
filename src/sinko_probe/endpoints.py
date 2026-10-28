"""Parse resolver addresses such as ``192.168.1.2``, ``[::1]:5353``, ``tls://dns.example``
or ``https://dns.example/dns-query``."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import TransportProtocol

DEFAULT_PORTS = {
    TransportProtocol.UDP: 53,
    TransportProtocol.TCP: 53,
    TransportProtocol.DOT: 853,
    TransportProtocol.DOH: 443,
}
SCHEMES = {
    "udp": TransportProtocol.UDP,
    "tcp": TransportProtocol.TCP,
    "tls": TransportProtocol.DOT,
    "dot": TransportProtocol.DOT,
    "https": TransportProtocol.DOH,
}
_DISPLAY_SCHEMES = {
    TransportProtocol.UDP: "udp",
    TransportProtocol.TCP: "tcp",
    TransportProtocol.DOT: "tls",
}
_HOSTNAME = re.compile(r"[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?")


class EndpointError(ValueError):
    """A resolver address could not be parsed."""


@dataclass(frozen=True)
class Endpoint:
    protocol: TransportProtocol
    host: str
    port: int
    path: str = "/dns-query"  # Only used for DoH

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    @property
    def _url_host(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def url(self) -> str:
        port = "" if self.port == DEFAULT_PORTS[TransportProtocol.DOH] else f":{self.port}"
        return f"https://{self._url_host}{port}{self.path}"

    def display(self) -> str:
        if self.protocol == TransportProtocol.DOH:
            return self.url
        return f"{_DISPLAY_SCHEMES[self.protocol]}://{self._url_host}:{self.port}"


def parse_endpoint(
    spec: str,
    default_protocol: TransportProtocol = TransportProtocol.UDP,
    port: int | None = None,
) -> Endpoint:
    """Turn a resolver address into an :class:`Endpoint`.

    A scheme (``udp://``, ``tcp://``, ``tls://`` or ``https://``) overrides
    ``default_protocol``, and a port written in the address overrides ``port``.
    """
    text = spec.strip()
    if not text:
        raise EndpointError("resolver address is empty")

    scheme, separator, rest = text.partition("://")
    if separator:
        protocol = SCHEMES.get(scheme.lower())
        if protocol is None:
            known = ", ".join(f"{s}://" for s in SCHEMES)
            raise EndpointError(f"unknown scheme {scheme!r} in {spec!r} (use {known})")
    else:
        protocol, rest = default_protocol, text

    if protocol == TransportProtocol.DOH:
        return _parse_doh(rest, spec, port)

    host, written_port = _split_host_port(rest, spec)
    return Endpoint(protocol, host, written_port or port or DEFAULT_PORTS[protocol])


def _parse_doh(rest: str, spec: str, port: int | None) -> Endpoint:
    parts = urlsplit(f"https://{rest}")
    try:
        written_port = parts.port
    except ValueError as exc:
        raise EndpointError(f"invalid port in {spec!r}") from exc
    host = parts.hostname
    if not host:
        raise EndpointError(f"no host in DoH URL {spec!r}")
    _check_host(host, spec)
    path = parts.path if parts.path not in ("", "/") else "/dns-query"
    return Endpoint(
        TransportProtocol.DOH,
        host,
        written_port or port or DEFAULT_PORTS[TransportProtocol.DOH],
        path,
    )


def _split_host_port(rest: str, spec: str) -> tuple[str, int | None]:
    if rest.startswith("["):
        host, bracket, tail = rest[1:].partition("]")
        if not bracket or (tail and not tail.startswith(":")):
            raise EndpointError(f"malformed bracketed IPv6 address in {spec!r}")
        port_text = tail[1:] or None
    elif rest.count(":") == 1:
        host, port_text = rest.split(":")
    else:
        host, port_text = rest, None  # Bare IPv6 address or a host without a port

    host = host.strip().lower()
    _check_host(host, spec)
    if port_text is None:
        return host, None
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise EndpointError(f"invalid port {port_text!r} in {spec!r}")
    return host, int(port_text)


def _check_host(host: str, spec: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.fullmatch(host):
            raise EndpointError(f"invalid resolver host {host!r} in {spec!r}") from None
