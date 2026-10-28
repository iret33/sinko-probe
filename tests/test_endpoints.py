import pytest

from sinko_probe.endpoints import EndpointError, parse_endpoint
from sinko_probe.models import TransportProtocol as P


@pytest.mark.parametrize(
    ("spec", "protocol", "host", "port", "display"),
    [
        ("192.168.1.2", P.UDP, "192.168.1.2", 53, "udp://192.168.1.2:53"),
        ("192.168.1.2:5353", P.UDP, "192.168.1.2", 5353, "udp://192.168.1.2:5353"),
        (
            "2606:4700:4700::1113",
            P.UDP,
            "2606:4700:4700::1113",
            53,
            "udp://[2606:4700:4700::1113]:53",
        ),
        ("[2606:4700:4700::1113]:5300", P.UDP, "2606:4700:4700::1113", 5300, None),
        ("[::1]", P.UDP, "::1", 53, "udp://[::1]:53"),
        ("sinko.local", P.UDP, "sinko.local", 53, "udp://sinko.local:53"),
        ("tcp://10.0.0.1", P.TCP, "10.0.0.1", 53, "tcp://10.0.0.1:53"),
        ("tls://1.1.1.3", P.DOT, "1.1.1.3", 853, "tls://1.1.1.3:853"),
        ("TLS://family.cloudflare-dns.com:8853", P.DOT, "family.cloudflare-dns.com", 8853, None),
        ("dot://dns.quad9.net", P.DOT, "dns.quad9.net", 853, None),
        (
            "https://family.cloudflare-dns.com/dns-query",
            P.DOH,
            "family.cloudflare-dns.com",
            443,
            "https://family.cloudflare-dns.com/dns-query",
        ),
        ("https://1.1.1.3", P.DOH, "1.1.1.3", 443, "https://1.1.1.3/dns-query"),
        ("https://[::1]:8443/custom/path", P.DOH, "::1", 8443, "https://[::1]:8443/custom/path"),
        ("https://dns.nextdns.io/abc123", P.DOH, "dns.nextdns.io", 443, None),
    ],
)
def test_parse_endpoint(spec, protocol, host, port, display):
    endpoint = parse_endpoint(spec)
    assert (endpoint.protocol, endpoint.host, endpoint.port) == (protocol, host, port)
    if display:
        assert endpoint.display() == display


def test_default_protocol_and_port_override():
    assert parse_endpoint("9.9.9.9", P.DOT).port == 853
    assert parse_endpoint("9.9.9.9", P.TCP, port=5353).port == 5353
    # A port written in the address is more specific than --port.
    assert parse_endpoint("9.9.9.9:5300", P.UDP, port=5353).port == 5300
    doh = parse_endpoint("192.168.1.2", P.DOH, port=8443)
    assert doh.url == "https://192.168.1.2:8443/dns-query"


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "   ",
        "ftp://1.1.1.1",
        "[::1",
        "[::1]x",
        "host:99999",
        "host:abc",
        "host:",
        "bad host",
        "https://",
    ],
)
def test_rejects_malformed_endpoints(spec):
    with pytest.raises(EndpointError):
        parse_endpoint(spec)
