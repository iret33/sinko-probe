import ipaddress

import dns.edns
import dns.message
import dns.name
import dns.rcode
import dns.rrset
import pytest

from sinko_probe.classify import MarkerSet, classify_response, outcome_for, parse_sinkholes
from sinko_probe.models import ExpectedAction, Outcome, Verdict

QNAME = dns.name.from_text("ads.tracker.example")
SOA = "ns1.example. hostmaster.example. 1 7200 3600 1209600 300"


def make_response(rcode=dns.rcode.NOERROR, answers=(), authority=(), ede=None):
    query = dns.message.make_query(QNAME, "A", use_edns=0)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    response.answer.extend(answers)
    response.authority.extend(authority)
    if ede is not None:
        response.use_edns(0, options=[dns.edns.EDEOption(ede)])
    return response


def a_record(*addresses, name=QNAME):
    return dns.rrset.from_text(name, 60, "IN", "A", *addresses)


def classify(response, **kwargs):
    return classify_response(response, QNAME, **kwargs)


def test_nxdomain_without_soa_is_a_block():
    assert classify(make_response(dns.rcode.NXDOMAIN)).verdict == Verdict.BLOCKED_NXDOMAIN


def test_nxdomain_with_upstream_soa_is_inconclusive():
    """A genuine 'does not exist' answer carries the enclosing zone's SOA; it proves nothing
    about filtering (dead probe domains and --cache-bust labels used to count as blocks)."""
    soa = dns.rrset.from_text("tracker.example.", 300, "IN", "SOA", SOA)
    result = classify(make_response(dns.rcode.NXDOMAIN, authority=[soa]))
    assert result.verdict == Verdict.UPSTREAM_NXDOMAIN
    assert "tracker.example." in result.detail


def test_nxdomain_with_soa_owned_by_the_query_name_is_a_block():
    # Blockers such as AdGuard Home synthesize an SOA owned by the blocked name itself.
    soa = dns.rrset.from_text(QNAME, 300, "IN", "SOA", SOA)
    assert classify(make_response(dns.rcode.NXDOMAIN, authority=[soa])).verdict == (
        Verdict.BLOCKED_NXDOMAIN
    )


def test_filtering_ede_overrides_the_upstream_soa():
    soa = dns.rrset.from_text("example.", 300, "IN", "SOA", SOA)
    result = classify(make_response(dns.rcode.NXDOMAIN, authority=[soa], ede=15))
    assert result.verdict == Verdict.BLOCKED_NXDOMAIN
    assert result.ede_codes == (15,)


def test_refused_is_a_block_unless_the_client_is_prohibited():
    assert classify(make_response(dns.rcode.REFUSED)).verdict == Verdict.BLOCKED_REFUSED
    prohibited = classify(make_response(dns.rcode.REFUSED, ede=18))
    assert prohibited.verdict == Verdict.ERROR_RCODE
    assert "not allowed" in prohibited.detail


def test_servfail_is_an_error_with_detail():
    result = classify(make_response(dns.rcode.SERVFAIL, ede=22))
    assert result.verdict == Verdict.ERROR_RCODE
    assert "SERVFAIL" in result.detail and "EDE 22" in result.detail


def test_empty_noerror_is_nodata():
    assert classify(make_response()).verdict == Verdict.BLOCKED_NODATA


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "127.0.0.53"])
def test_zero_and_loopback_answers_are_blocks(address):
    assert classify(make_response(answers=[a_record(address)])).verdict == Verdict.BLOCKED_ZERO_IP


def test_unspecified_ipv6_is_a_block():
    rrset = dns.rrset.from_text(QNAME, 60, "IN", "AAAA", "::")
    assert classify(make_response(answers=[rrset])).verdict == Verdict.BLOCKED_ZERO_IP


def test_sinkhole_ips_and_cidrs():
    sinkholes = parse_sinkholes(["192.168.1.2", "146.112.61.0/24"])
    for address in ("192.168.1.2", "146.112.61.106"):
        response = make_response(answers=[a_record(address)])
        assert classify(response, sinkholes=sinkholes).verdict == Verdict.BLOCKED_SINKHOLE_IP
    response = make_response(answers=[a_record("192.168.1.3")])
    assert classify(response, sinkholes=sinkholes).verdict == Verdict.ALLOWED_RESOLVED


def test_parse_sinkholes_rejects_garbage():
    with pytest.raises(ValueError, match="sinkhole"):
        parse_sinkholes(["not-an-ip"])


def test_filtered_ede_with_a_real_ip_means_block_page():
    response = make_response(answers=[a_record("203.0.113.9")], ede=17)
    assert classify(response).verdict == Verdict.BLOCKED_SINKHOLE_IP


def test_safesearch_cname_matches_name_and_subdomain():
    markers = MarkerSet.parse(["forcesafesearch.google.com"])
    for target in ("forcesafesearch.google.com.", "edge.forcesafesearch.google.com."):
        rrset = dns.rrset.from_text(QNAME, 60, "IN", "CNAME", target)
        response = make_response(answers=[rrset, a_record("216.239.38.120", name=target)])
        assert classify(response, markers=markers).verdict == Verdict.SAFESEARCH_ENFORCED


def test_safesearch_vip_matches_exactly():
    markers = MarkerSet.parse(["216.239.38.120"])
    response = make_response(answers=[a_record("216.239.38.120")])
    assert classify(response, markers=markers).verdict == Verdict.SAFESEARCH_ENFORCED


def test_markers_are_not_substring_matches():
    """The old engine used ``marker in target``: 'strict.bing.com.evil.example' and the IP
    '11.2.3.45' (containing '1.2.3.4') both counted as SafeSearch enforcement."""
    markers = MarkerSet.parse(["strict.bing.com", "1.2.3.4"])
    rrset = dns.rrset.from_text(QNAME, 60, "IN", "CNAME", "strict.bing.com.evil.example.")
    spoofed = make_response(
        answers=[rrset, a_record("11.2.3.45", name="strict.bing.com.evil.example.")]
    )
    assert classify(spoofed, markers=markers).verdict == Verdict.ALLOWED_RESOLVED


def test_marker_set_splits_names_and_addresses():
    markers = MarkerSet.parse(["Restrict.YouTube.com.", "216.239.38.119", "2001:db8::1"])
    assert markers.names == {"restrict.youtube.com"}
    assert markers.addresses == {
        ipaddress.ip_address("216.239.38.119"),
        ipaddress.ip_address("2001:db8::1"),
    }
    assert not MarkerSet.parse([])


@pytest.mark.parametrize(
    ("expected", "verdict", "outcome"),
    [
        (ExpectedAction.BLOCK, Verdict.BLOCKED_NXDOMAIN, Outcome.PASS),
        (ExpectedAction.BLOCK, Verdict.ALLOWED_RESOLVED, Outcome.FAIL),
        (ExpectedAction.BLOCK, Verdict.SAFESEARCH_ENFORCED, Outcome.FAIL),
        (ExpectedAction.ALLOW, Verdict.ALLOWED_RESOLVED, Outcome.PASS),
        (ExpectedAction.ALLOW, Verdict.SAFESEARCH_ENFORCED, Outcome.PASS),
        (ExpectedAction.ALLOW, Verdict.BLOCKED_ZERO_IP, Outcome.FAIL),
        (ExpectedAction.SAFESEARCH, Verdict.SAFESEARCH_ENFORCED, Outcome.PASS),
        (ExpectedAction.SAFESEARCH, Verdict.ALLOWED_RESOLVED, Outcome.FAIL),
        (ExpectedAction.ALLOW, Verdict.ERROR_TIMEOUT, Outcome.ERROR),
        (ExpectedAction.BLOCK, Verdict.ERROR_TRANSPORT, Outcome.ERROR),
        (ExpectedAction.BLOCK, Verdict.UPSTREAM_NXDOMAIN, Outcome.INCONCLUSIVE),
    ],
)
def test_outcome_for(expected, verdict, outcome):
    assert outcome_for(expected, verdict) == outcome
