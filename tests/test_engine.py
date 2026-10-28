import pytest
from unittest.mock import AsyncMock, patch
import dns.message
import dns.name
import dns.rcode
import dns.rrset

from sinko_probe.engine import DNSSimulatorEngine
from sinko_probe.models import AppProfile, Category, DomainProbe, ExpectedAction, Verdict


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
                domain="ads.example.com",
                category=Category.ADS,
                expected=ExpectedAction.BLOCK,
            ),
            DomainProbe(
                domain="www.google.com",
                category=Category.SAFE_SEARCH,
                expected=ExpectedAction.SAFESEARCH,
                expected_cname_markers=["forcesafesearch.google.com"],
            ),
        ],
    )


@pytest.mark.asyncio
async def test_nxdomain_verdict(sample_profile: AppProfile):
    engine = DNSSimulatorEngine(nameserver="127.0.0.1", realistic_jitter=False)
    q = dns.message.make_query("ads.example.com", "A")
    resp = dns.message.make_response(q)
    resp.set_rcode(dns.rcode.NXDOMAIN)

    with patch.object(engine, "_raw_query", new=AsyncMock(return_value=resp)):
        result = await engine.probe_single(sample_profile, sample_profile.probes[0])
        assert result.verdict == Verdict.BLOCKED_NXDOMAIN
        assert result.passed_expectation is True


@pytest.mark.asyncio
async def test_safesearch_cname_detection(sample_profile: AppProfile):
    engine = DNSSimulatorEngine(nameserver="127.0.0.1", realistic_jitter=False)
    q = dns.message.make_query("www.google.com", "A")
    resp = dns.message.make_response(q)
    cname_rr = dns.rrset.from_text(
        "www.google.com.", 300, "IN", "CNAME", "forcesafesearch.google.com."
    )
    resp.answer.append(cname_rr)

    with patch.object(engine, "_raw_query", new=AsyncMock(return_value=resp)):
        result = await engine.probe_single(sample_profile, sample_profile.probes[1])
        assert result.verdict == Verdict.SAFESEARCH_ENFORCED
        assert result.passed_expectation is True
