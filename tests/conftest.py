import ssl
from pathlib import Path

import pytest
import trustme
from fakedns import FakeDNSServer, answer, cname

from sinko_probe.models import ExpectedAction
from sinko_probe.profiles import BUILTIN_PROFILES


def configure_perfect_sinko(server: FakeDNSServer) -> None:
    """Make the fake resolver behave like a correctly configured Sinko box for every built-in
    profile: must-block names (and their subdomains) sinkhole to 0.0.0.0, must-allow names
    resolve, and search engines are rewritten to their SafeSearch CNAMEs."""
    allowed_ip = 10
    for profile in BUILTIN_PROFILES.values():
        for probe in profile.probes:
            if probe.expected == ExpectedAction.BLOCK:
                server.set(probe.domain, answer("0.0.0.0"))
                server.set(f"*.{probe.domain}", answer("0.0.0.0"))
            elif probe.expected == ExpectedAction.ALLOW:
                allowed_ip += 1
                server.set(probe.domain, answer(f"198.51.100.{allowed_ip}"))
            else:
                target = next(m for m in probe.expected_cname_markers if not m[0].isdigit())
                server.set(probe.domain, cname(target, "216.239.38.120"))


@pytest.fixture
def fake_dns():
    server = FakeDNSServer().start()
    yield server
    server.stop()


@pytest.fixture
def perfect_sinko(fake_dns: FakeDNSServer) -> FakeDNSServer:
    configure_perfect_sinko(fake_dns)
    return fake_dns


@pytest.fixture(scope="session")
def certificate_authority() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(scope="session")
def ca_file(certificate_authority: trustme.CA, tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("ca") / "sinko-ca.pem"
    certificate_authority.cert_pem.write_to_path(str(path))
    return path


@pytest.fixture
def server_tls(certificate_authority: trustme.CA):
    """Return a factory for server-side TLS contexts with a cert for 127.0.0.1 and sinko.test."""
    cert = certificate_authority.issue_cert("127.0.0.1", "sinko.test")

    def make(alpn: list[str]) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cert.configure_cert(context)
        context.set_alpn_protocols(alpn)
        return context

    return make
