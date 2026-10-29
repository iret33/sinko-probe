"""Scoring, grouping and diagnostics over probe results."""

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field

from .models import (
    ExpectedAction,
    Outcome,
    ProbeResult,
    TargetSummary,
    TransportProtocol,
    Verdict,
)


def compute_percentile(sorted_vals: Sequence[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lower = math.floor(idx)
    upper = math.ceil(idx)
    if lower == upper:
        return round(sorted_vals[int(idx)], 2)
    weight = idx - lower
    return round(sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight, 2)


def percent(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator * 100, 1) if denominator else None


@dataclass(frozen=True)
class Tally:
    """How many conclusive probes with one expectation met it."""

    passed: int = 0
    conclusive: int = 0

    @property
    def rate(self) -> float | None:
        return percent(self.passed, self.conclusive)


def tally(results: Sequence[ProbeResult], expected: ExpectedAction) -> Tally:
    conclusive = [
        r for r in results if r.expected == expected and r.outcome in (Outcome.PASS, Outcome.FAIL)
    ]
    return Tally(sum(r.outcome == Outcome.PASS for r in conclusive), len(conclusive))


def answered_latencies(results: Sequence[ProbeResult]) -> list[float]:
    """Latencies of probes that got an answer; timeouts would only measure the timeout."""
    return sorted(r.latency_ms for r in results if not r.verdict.is_error)


def summarize_results(
    results: Sequence[ProbeResult],
    *,
    target_name: str,
    server_endpoint: str,
    protocol: TransportProtocol,
    policy_name: str | None = None,
) -> TargetSummary:
    outcomes = Counter(r.outcome for r in results)
    total = len(results)
    allow = tally(results, ExpectedAction.ALLOW)
    latencies = answered_latencies(results)

    def latency(pct: float) -> float | None:
        return compute_percentile(latencies, pct) if latencies else None

    return TargetSummary(
        target_name=target_name,
        server_endpoint=server_endpoint,
        protocol=protocol,
        policy_name=policy_name,
        iterations=max((r.wave for r in results), default=1),
        total_probes=total,
        passed_probes=outcomes[Outcome.PASS],
        failed_probes=outcomes[Outcome.FAIL],
        error_probes=outcomes[Outcome.ERROR],
        inconclusive_probes=outcomes[Outcome.INCONCLUSIVE],
        compliance_score=percent(outcomes[Outcome.PASS], total - outcomes[Outcome.INCONCLUSIVE]),
        block_rate=tally(results, ExpectedAction.BLOCK).rate,
        # A must-allow probe can only fail by being blocked, so its failure rate is the
        # over-blocking (false-positive) rate.
        false_positive_rate=percent(allow.conclusive - allow.passed, allow.conclusive),
        safesearch_rate=tally(results, ExpectedAction.SAFESEARCH).rate,
        error_rate=percent(outcomes[Outcome.ERROR], total) or 0.0,
        p50_ms=latency(50),
        p95_ms=latency(95),
        p99_ms=latency(99),
    )


@dataclass
class ProbeGroup:
    """All waves of one probe (same app, domain and record type)."""

    results: list[ProbeResult] = field(default_factory=list)

    @property
    def first(self) -> ProbeResult:
        return self.results[0]

    @property
    def runs(self) -> int:
        return len(self.results)

    @property
    def passes(self) -> int:
        return sum(r.outcome == Outcome.PASS for r in self.results)

    @property
    def outcome(self) -> Outcome:
        outcomes = {r.outcome for r in self.results}
        for worst in (Outcome.FAIL, Outcome.ERROR, Outcome.INCONCLUSIVE):
            if worst in outcomes:
                return worst
        return Outcome.PASS

    @property
    def verdict(self) -> Verdict:
        return Counter(r.verdict for r in self.results).most_common(1)[0][0]

    @property
    def latest_answer(self) -> ProbeResult:
        answered = [r for r in self.results if not r.verdict.is_error]
        return (answered or self.results)[-1]

    @property
    def median_latency_ms(self) -> float | None:
        latencies = answered_latencies(self.results)
        return round(statistics.median(latencies), 1) if latencies else None


def group_results(results: Sequence[ProbeResult]) -> list[ProbeGroup]:
    groups: dict[tuple[str, str, str], ProbeGroup] = {}
    for result in results:
        key = (result.app_id, result.domain, result.record_type)
        groups.setdefault(key, ProbeGroup()).results.append(result)
    return list(groups.values())


def results_by_app(results: Sequence[ProbeResult]) -> dict[str, list[ProbeResult]]:
    by_app: dict[str, list[ProbeResult]] = defaultdict(list)
    for result in results:
        by_app[result.app_id].append(result)
    return dict(by_app)


@dataclass(frozen=True)
class Hint:
    """A diagnostic for the reporters; ``key`` selects a translated message template."""

    key: str
    params: dict[str, str | int] = field(default_factory=dict)


def find_hints(results: Sequence[ProbeResult]) -> list[Hint]:
    if not results:
        return []
    if all(r.verdict.is_error for r in results):
        return [Hint("no_answers", {"error": results[0].error_message or results[0].verdict.value})]

    hints = []
    answered = [r for r in results if not r.verdict.is_error]
    if all(r.verdict == Verdict.BLOCKED_REFUSED for r in answered):
        hints.append(Hint("all_refused"))
    errors = sum(r.verdict.is_error for r in results)
    if errors:
        hints.append(Hint("some_errors", {"count": errors, "total": len(results)}))
    dead = sorted({r.domain for r in results if r.outcome == Outcome.INCONCLUSIVE})
    if dead:
        hints.append(Hint("inconclusive", {"count": len(dead), "domains": ", ".join(dead[:5])}))
    suggestion = suggest_sinkhole_ip(results)
    if suggestion:
        address, count = suggestion
        hints.append(Hint("sinkhole", {"ip": address, "count": count}))
    return hints


def suggest_sinkhole_ip(results: Sequence[ProbeResult]) -> tuple[str, int] | None:
    """Spot an unconfigured block page: one IP answered alone for many unrelated must-block
    domains, and never for a must-allow domain."""
    allowed_ips = {
        ip for r in results if r.expected == ExpectedAction.ALLOW for ip in r.resolved_ips
    }
    sites_by_ip: dict[str, set[str]] = defaultdict(set)
    for r in results:
        if (
            r.expected == ExpectedAction.BLOCK
            and r.verdict == Verdict.ALLOWED_RESOLVED
            and len(r.resolved_ips) == 1
            and r.resolved_ips[0] not in allowed_ips
        ):
            sites_by_ip[r.resolved_ips[0]].add(".".join(r.domain.split(".")[-2:]))
    if not sites_by_ip:
        return None
    address, sites = max(sites_by_ip.items(), key=lambda item: len(item[1]))
    return (address, len(sites)) if len(sites) >= 3 else None
