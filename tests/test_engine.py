import asyncio
import socket
from unittest.mock import AsyncMock, patch

import dns.message
import dns.rcode
import dns.rrset
import pytest
from fakedns import FakeDNSServer, answer, cname, drop, hangup, nxdomain, truncated_over_udp

from sinko_probe.engine import (
    CACHE_BUST_PREFIX,
    DNSSimulatorEngine,
    build_plan,
)
from sinko_probe.models import (
    AppProfile,
    Category,
    DomainProbe,
    ExpectedAction,
    Outcome,
    TransportProtocol,
    Verdict,
)
from sinko_probe.profiles import BUILTIN_PROFILES

ALL_PROFILES = list(BUILTIN_PROFILES.values())


@pytest.fixture
def sample_profile() -> AppProfile:
    return AppProfile(
        id="test_suite",
        name="Test Suite",
        name_ar="مجموعة اختبار",
        description="Unit test profile",
        burst_interval_ms=(1, 2),
        probes=[
            DomainProbe(
                domain="ads.example.com", category=Category.ADS, expected=ExpectedAction.BLOCK
            ),
            DomainProbe(
                domain="www.google.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=["forcesafesearch.google.com"],
            ),
            DomainProbe(
                domain="www.wikipedia.org",
                category=Category.CORE_SERVICE,
                expected=ExpectedAction.ALLOW,
            ),
        ],
    )


def engine_for(server: FakeDNSServer, **kwargs) -> DNSSimulatorEngine:
    kwargs.setdefault("realistic_jitter", False)
    return DNSSimulatorEngine(nameserver="127.0.0.1", port=server.port, **kwargs)


# -- verdicts with a mocked transport (the original tests, still valid) ------------------------


@pytest.mark.asyncio
async def test_nxdomain_verdict(sample_profile: AppProfile):
    engine = DNSSimulatorEngine(nameserver="127.0.0.1", realistic_jitter=False)
    q = dns.message.make_query("ads.example.com", "A")
    resp = dns.message.make_response(q)
    resp.set_rcode(dns.rcode.NXDOMAIN)

    with patch.object(engine, "_send", new=AsyncMock(return_value=resp)):
        result = await engine.probe_single(sample_profile, sample_profile.probes[0])
    assert result.verdict == Verdict.BLOCKED_NXDOMAIN
    assert result.passed_expectation is True


@pytest.mark.asyncio
async def test_safesearch_cname_detection(sample_profile: AppProfile):
    engine = DNSSimulatorEngine(nameserver="127.0.0.1", realistic_jitter=False)
    q = dns.message.make_query("www.google.com", "A")
    resp = dns.message.make_response(q)
    resp.answer.append(
        dns.rrset.from_text("www.google.com.", 300, "IN", "CNAME", "forcesafesearch.google.com.")
    )

    with patch.object(engine, "_send", new=AsyncMock(return_value=resp)):
        result = await engine.probe_single(sample_profile, sample_profile.probes[1])
    assert result.verdict == Verdict.SAFESEARCH_ENFORCED
    assert result.passed_expectation is True


@pytest.mark.asyncio
async def test_programming_errors_are_not_disguised_as_dns_errors(sample_profile: AppProfile):
    """The old ``except Exception`` turned bugs (like DoH's bad ``session=`` keyword) into
    'ERROR (Timeout/ServFail)' verdicts, so DoH never worked and nothing said why."""
    engine = DNSSimulatorEngine(nameserver="127.0.0.1", realistic_jitter=False)
    with (
        patch.object(engine, "_send", new=AsyncMock(side_effect=TypeError("bad kwarg"))),
        pytest.raises(TypeError),
    ):
        await engine.probe_single(sample_profile, sample_profile.probes[0])


# -- real UDP / TCP round trips ----------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol", [TransportProtocol.UDP, TransportProtocol.TCP])
async def test_perfect_sinko_scores_100(perfect_sinko: FakeDNSServer, protocol):
    engine = engine_for(perfect_sinko, protocol=protocol)
    results = await engine.run_simulation(ALL_PROFILES)
    failures = [(r.domain, r.verdict) for r in results if r.outcome != Outcome.PASS]
    assert failures == []
    summary = engine.summarize(results)
    assert summary.compliance_score == 100.0
    assert summary.block_rate == summary.safesearch_rate == 100.0
    assert summary.false_positive_rate == 0.0
    assert {t for t, _ in perfect_sinko.queries} == {protocol.value}


@pytest.mark.asyncio
async def test_truncated_udp_answers_are_retried_over_tcp(fake_dns: FakeDNSServer, sample_profile):
    """A truncated (TC) UDP answer has no records; the old engine called that 'BLOCKED'."""
    fake_dns.set("www.wikipedia.org", truncated_over_udp(answer("198.51.100.20")))
    engine = engine_for(fake_dns)
    result = await engine.probe_single(sample_profile, sample_profile.probes[2])
    assert result.verdict == Verdict.ALLOWED_RESOLVED
    assert result.resolved_ips == ["198.51.100.20"]
    assert [t for t, _ in fake_dns.queries] == ["udp", "tcp"]


@pytest.mark.asyncio
async def test_timeouts_are_errors_and_stay_out_of_the_rates(fake_dns, sample_profile):
    fake_dns.set("ads.example.com", answer("0.0.0.0"))
    fake_dns.set("www.google.com", cname("forcesafesearch.google.com", "216.239.38.120"))
    fake_dns.set("www.wikipedia.org", drop())
    engine = engine_for(fake_dns, timeout=0.3)
    results = await engine.run_simulation([sample_profile])
    by_domain = {r.domain: r for r in results}
    assert by_domain["www.wikipedia.org"].verdict == Verdict.ERROR_TIMEOUT
    assert by_domain["www.wikipedia.org"].outcome == Outcome.ERROR
    summary = engine.summarize(results)
    assert summary.false_positive_rate is None  # nothing conclusive to judge
    assert summary.error_probes == 1
    assert summary.p99_ms < 300


@pytest.mark.asyncio
async def test_server_hanging_up_is_a_transport_error(fake_dns: FakeDNSServer, sample_profile):
    # dnspython raises EOFError (not an OSError) when a TCP/TLS peer closes without answering.
    fake_dns.set("ads.example.com", hangup())
    engine = engine_for(fake_dns, protocol=TransportProtocol.TCP, timeout=2)
    result = await engine.probe_single(sample_profile, sample_profile.probes[0])
    assert result.verdict == Verdict.ERROR_TRANSPORT
    assert "EOFError" in result.error_message


@pytest.mark.asyncio
async def test_queries_carry_edns_so_ede_codes_come_back(fake_dns: FakeDNSServer, sample_profile):
    fake_dns.set("ads.example.com", nxdomain(soa_owner="example.com", ede=(15, "Blocked")))
    engine = engine_for(fake_dns)
    result = await engine.probe_single(sample_profile, sample_profile.probes[0])
    assert result.verdict == Verdict.BLOCKED_NXDOMAIN
    assert result.ede_codes == [15]


# -- cache busting / wildcard checks -------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_bust_only_randomizes_must_block_names(fake_dns: FakeDNSServer, sample_profile):
    """Randomizing allowed or SafeSearch names makes them NXDOMAIN upstream, which the old engine
    reported as 100% false positives and 0% SafeSearch."""
    fake_dns.set("*.ads.example.com", answer("0.0.0.0"))
    fake_dns.set("www.google.com", cname("forcesafesearch.google.com", "216.239.38.120"))
    fake_dns.set("www.wikipedia.org", answer("198.51.100.7"))
    engine = engine_for(fake_dns, cache_bust=True, seed=7)
    results = await engine.run_simulation([sample_profile])
    by_domain = {r.domain: r for r in results}
    assert by_domain["ads.example.com"].qname.startswith(CACHE_BUST_PREFIX)
    assert by_domain["ads.example.com"].qname.endswith(".ads.example.com")
    assert by_domain["www.google.com"].qname == "www.google.com"
    assert by_domain["www.wikipedia.org"].qname == "www.wikipedia.org"
    assert all(r.outcome == Outcome.PASS for r in results)


@pytest.mark.asyncio
async def test_cache_bust_upstream_nxdomain_is_not_counted_as_blocked(fake_dns, sample_profile):
    # A resolver with no wildcard rule passes the random name upstream, which says NXDOMAIN.
    fake_dns.set("ads.example.com", answer("0.0.0.0"))
    fake_dns.set("*.ads.example.com", nxdomain(soa_owner="example.com"))
    engine = engine_for(fake_dns, cache_bust=True)
    result = await engine.probe_single(sample_profile, sample_profile.probes[0])
    assert result.verdict == Verdict.UPSTREAM_NXDOMAIN
    assert result.outcome == Outcome.INCONCLUSIVE


# -- scheduling --------------------------------------------------------------------------------


def test_jitter_replays_each_app_as_a_burst():
    """Old 'jitter' slept 25-250 ms from t=0 for every query, so all apps fired in the same
    quarter second. Now each app's queries are spaced by its burst interval."""
    engine = DNSSimulatorEngine(seed=1)
    plan = build_plan([BUILTIN_PROFILES["youtube_app"], BUILTIN_PROFILES["roblox_gaming"]])
    schedule = engine._schedule(plan)
    for profile_id in ("youtube_app", "roblox_gaming"):
        offsets = [delay for planned, delay in schedule if planned.profile.id == profile_id]
        gaps = [b - a for a, b in zip([0.0, *offsets], offsets)]
        assert all(0.025 <= gap <= 0.25 for gap in gaps)
    assert all(
        delay == 0 for _, delay in DNSSimulatorEngine(realistic_jitter=False)._schedule(plan)
    )


@pytest.mark.asyncio
async def test_waves_run_in_order(perfect_sinko: FakeDNSServer, sample_profile):
    perfect_sinko.set("ads.example.com", answer("0.0.0.0"))
    engine = engine_for(perfect_sinko)
    results = await engine.run_simulation([sample_profile], iterations=3)
    assert [r.wave for r in results] == [1, 1, 1, 2, 2, 2, 3, 3, 3]
    assert engine.summarize(results).iterations == 3


@pytest.mark.asyncio
async def test_engine_can_run_twice_in_different_event_loops(perfect_sinko, sample_profile):
    # The old engine created its asyncio.Semaphore in __init__, outside any running loop.
    engine = engine_for(perfect_sinko)
    first = await engine.run_simulation([sample_profile])
    second = await engine.run_simulation([sample_profile])
    assert len(first) == len(second) == 3


# -- resolver hostnames ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolver_hostname_is_resolved_first(perfect_sinko, sample_profile, monkeypatch):
    """dnspython needs an IP; a hostname like 'sinko.local' used to fail every single query."""
    perfect_sinko.set("ads.example.com", answer("0.0.0.0"))

    async def fake_getaddrinfo(host, port, **kwargs):
        assert host == "sinko.local"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
    engine = DNSSimulatorEngine(
        nameserver="sinko.local", port=perfect_sinko.port, realistic_jitter=False
    )
    results = await engine.run_simulation([sample_profile])
    assert all(r.outcome == Outcome.PASS for r in results)


@pytest.mark.asyncio
async def test_unresolvable_resolver_hostname_is_reported_on_every_probe(
    sample_profile, monkeypatch
):
    async def failing_getaddrinfo(host, port, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", failing_getaddrinfo)
    engine = DNSSimulatorEngine(nameserver="no-such-box.invalid", realistic_jitter=False)
    results = await engine.run_simulation([sample_profile])
    assert {r.verdict for r in results} == {Verdict.ERROR_TRANSPORT}
    assert all("no-such-box.invalid" in r.error_message for r in results)
    assert engine.summarize(results).error_probes == len(results)


# -- DNS-over-TLS --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dot_verifies_certificates(perfect_sinko, server_tls, ca_file, sample_profile):
    """The old DoT code set CERT_NONE, so any machine-in-the-middle passed the audit."""
    perfect_sinko.set("ads.example.com", answer("0.0.0.0"))
    port = perfect_sinko.start_tls(server_tls(["dot"]))

    def dot(**kwargs):
        return DNSSimulatorEngine(
            nameserver=f"tls://127.0.0.1:{port}", realistic_jitter=False, timeout=2, **kwargs
        )

    trusted = await dot(ca_file=ca_file).run_simulation([sample_profile])
    assert all(r.outcome == Outcome.PASS for r in trusted)

    untrusted = await dot().run_simulation([sample_profile])
    assert {r.verdict for r in untrusted} == {Verdict.ERROR_TRANSPORT}
    assert "certificate verify failed" in untrusted[0].error_message.lower()

    insecure = await dot(insecure=True).run_simulation([sample_profile])
    assert all(r.outcome == Outcome.PASS for r in insecure)

    by_name = await dot(ca_file=ca_file, tls_server_name="sinko.test").run_simulation(
        [sample_profile]
    )
    assert all(r.outcome == Outcome.PASS for r in by_name)

    wrong_name = await dot(ca_file=ca_file, tls_server_name="evil.test").run_simulation(
        [sample_profile]
    )
    assert {r.verdict for r in wrong_name} == {Verdict.ERROR_TRANSPORT}


# -- DNS-over-HTTPS ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_doh_round_trip_reuses_one_connection(perfect_sinko, server_tls, ca_file):
    """The old DoH call passed ``session=`` (not a dnspython argument), so every DoH probe
    failed; it also opened a fresh TLS connection per query, inflating latency."""
    port = perfect_sinko.start_doh(server_tls(["http/1.1"]))
    engine = DNSSimulatorEngine(
        nameserver=f"https://127.0.0.1:{port}/dns-query",
        ca_file=ca_file,
        concurrency=1,
        realistic_jitter=False,
    )
    profile = BUILTIN_PROFILES["sinko_family_shield"]
    results = await engine.run_simulation([profile])
    assert all(r.outcome == Outcome.PASS for r in results), [(r.domain, r.verdict) for r in results]
    assert {t for t, _ in perfect_sinko.queries} == {"https"}
    assert perfect_sinko.connections["https"] == 1
    assert engine.summarize(results).server_endpoint == f"https://127.0.0.1:{port}/dns-query"


@pytest.mark.asyncio
async def test_doh_http_errors_are_transport_errors(
    perfect_sinko, server_tls, ca_file, sample_profile
):
    port = perfect_sinko.start_doh(server_tls(["http/1.1"]))
    engine = DNSSimulatorEngine(
        nameserver=f"https://127.0.0.1:{port}/wrong-path", ca_file=ca_file, realistic_jitter=False
    )
    result = await engine.probe_single(sample_profile, sample_profile.probes[0])
    assert result.verdict == Verdict.ERROR_TRANSPORT
    assert "HTTP 404" in result.error_message
