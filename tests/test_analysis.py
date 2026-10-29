import pytest

from sinko_probe.analysis import (
    compute_percentile,
    find_hints,
    group_results,
    suggest_sinkhole_ip,
    summarize_results,
)
from sinko_probe.classify import outcome_for
from sinko_probe.models import Category, ExpectedAction, Outcome, ProbeResult, TransportProtocol
from sinko_probe.models import Verdict as V

BLOCK, ALLOW, SAFESEARCH = ExpectedAction.BLOCK, ExpectedAction.ALLOW, ExpectedAction.SAFESEARCH


def result(domain, expected, verdict, latency=10.0, ips=(), app="app", wave=1, error=None):
    return ProbeResult(
        target_name="t",
        wave=wave,
        app_id=app,
        app_name=app,
        app_name_ar=app,
        domain=domain,
        record_type="A",
        category=Category.ADS,
        expected=expected,
        verdict=verdict,
        outcome=outcome_for(expected, verdict),
        resolved_ips=list(ips),
        latency_ms=latency,
        error_message=error,
    )


def summarize(results):
    return summarize_results(
        results, target_name="t", server_endpoint="udp://x:53", protocol=TransportProtocol.UDP
    )


def test_percentiles():
    assert compute_percentile([], 50) == 0.0
    assert compute_percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.5
    assert compute_percentile([5.0], 99) == 5.0


def test_timeouts_are_errors_not_false_positives():
    """The old summary counted an unreachable must-allow site as a false positive, and folded
    timeout durations into the latency percentiles."""
    summary = summarize(
        [
            result("wikipedia.org", ALLOW, V.ERROR_TIMEOUT, latency=3500.0),
            result("khanacademy.org", ALLOW, V.ALLOWED_RESOLVED, latency=12.0),
            result("ads.example", BLOCK, V.BLOCKED_ZERO_IP, latency=8.0),
        ]
    )
    assert summary.false_positive_rate == 0.0
    assert summary.block_rate == 100.0
    assert summary.error_probes == 1
    assert summary.error_rate == pytest.approx(33.3)
    assert summary.compliance_score == pytest.approx(66.7)
    assert summary.p99_ms < 20


def test_untested_rates_are_none_not_100_percent():
    summary = summarize([result("ads.example", BLOCK, V.BLOCKED_NXDOMAIN)])
    assert summary.safesearch_rate is None
    assert summary.false_positive_rate is None
    assert summary.block_rate == 100.0


def test_false_positive_rate_counts_blocked_allow_probes():
    summary = summarize(
        [
            result("a.org", ALLOW, V.BLOCKED_NXDOMAIN),
            result("b.org", ALLOW, V.ALLOWED_RESOLVED),
            result("c.org", ALLOW, V.ALLOWED_RESOLVED),
            result("d.org", ALLOW, V.ALLOWED_RESOLVED),
        ]
    )
    assert summary.false_positive_rate == 25.0


def test_inconclusive_probes_do_not_move_the_score():
    summary = summarize(
        [
            result("dead.example", BLOCK, V.UPSTREAM_NXDOMAIN),
            result("ads.example", BLOCK, V.BLOCKED_NODATA),
        ]
    )
    assert summary.inconclusive_probes == 1
    assert summary.compliance_score == 100.0
    assert summary.block_rate == 100.0


def test_empty_run():
    summary = summarize([])
    assert summary.compliance_score is None
    assert summary.p50_ms is None
    assert find_hints([]) == []


def test_groups_merge_waves_and_report_the_worst_outcome():
    groups = group_results(
        [
            result("ads.example", BLOCK, V.BLOCKED_ZERO_IP, wave=1, latency=10.0),
            result("ads.example", BLOCK, V.ALLOWED_RESOLVED, wave=2, latency=20.0),
            result("ads.example", BLOCK, V.ERROR_TIMEOUT, wave=3, latency=3500.0),
        ]
    )
    assert len(groups) == 1
    group = groups[0]
    assert (group.runs, group.passes, group.outcome) == (3, 1, Outcome.FAIL)
    assert group.median_latency_ms == 15.0
    assert group.latest_answer.verdict == V.ALLOWED_RESOLVED


def test_hint_when_nothing_answers():
    hints = find_hints([result("a", BLOCK, V.ERROR_TIMEOUT, error="no answer within 1s")])
    assert [h.key for h in hints] == ["no_answers"]
    assert "no answer" in hints[0].params["error"]


def test_hint_when_everything_is_refused():
    hints = find_hints(
        [result("a.example", BLOCK, V.BLOCKED_REFUSED), result("b.org", ALLOW, V.BLOCKED_REFUSED)]
    )
    assert "all_refused" in [h.key for h in hints]


def test_block_page_suggestion():
    results = [
        result(f"ads.site{i}.example", BLOCK, V.ALLOWED_RESOLVED, ips=["192.168.1.2"])
        for i in range(3)
    ] + [result("wikipedia.org", ALLOW, V.ALLOWED_RESOLVED, ips=["198.51.100.7"])]
    assert suggest_sinkhole_ip(results) == ("192.168.1.2", 3)
    assert "sinkhole" in [h.key for h in find_hints(results)]


def test_no_block_page_suggestion_for_shared_cdn_ips():
    results = [
        result("ad.doubleclick.net", BLOCK, V.ALLOWED_RESOLVED, ips=["142.250.1.1"]),
        result("googleads.g.doubleclick.net", BLOCK, V.ALLOWED_RESOLVED, ips=["142.250.1.1"]),
        result("pagead2.googlesyndication.com", BLOCK, V.ALLOWED_RESOLVED, ips=["142.250.1.1"]),
    ]
    assert suggest_sinkhole_ip(results) is None  # only two distinct sites
