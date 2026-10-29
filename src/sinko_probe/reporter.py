"""Terminal (Rich) reports plus JSON and CSV exports.

Everything that comes from the command line or from DNS answers is wrapped in ``Text`` so Rich
never parses it as markup: a CNAME containing ``[/]`` must not crash the report.
"""

import csv
import json
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .analysis import (
    Hint,
    ProbeGroup,
    answered_latencies,
    group_results,
    percent,
    results_by_app,
    tally,
)
from .i18n import (
    Lang,
    category_label,
    expected_label,
    format_ms,
    format_rate,
    outcome_label,
    t,
    verdict_label,
)
from .models import ExpectedAction, Outcome, ProbeResult, TargetSummary, Verdict

OUTCOME_STYLES = {
    Outcome.PASS: "bold green",
    Outcome.FAIL: "bold red",
    Outcome.ERROR: "bold magenta",
    Outcome.INCONCLUSIVE: "bold yellow",
}


def verdict_style(verdict: Verdict) -> str:
    if verdict.is_blocked or verdict == Verdict.SAFESEARCH_ENFORCED:
        return "green"
    if verdict.is_error:
        return "bold red"
    if verdict == Verdict.UPSTREAM_NXDOMAIN:
        return "magenta"
    return "yellow"


def score_style(score: float | None) -> str:
    if score is None:
        return "dim"
    return "green" if score >= 85 else ("yellow" if score >= 60 else "red")


def display_domain(result: ProbeResult) -> str:
    """Show cache-busted probes as the wildcard they test."""
    return result.domain if result.qname in (None, result.domain) else f"*.{result.domain}"


def answer_summary(result: ProbeResult, max_ips: int = 2) -> str:
    if result.verdict.is_error:
        return result.error_message or "-"
    parts = []
    if result.cname_chain:
        parts.append(f"CNAME {result.cname_chain[0]}")
    if result.resolved_ips:
        extra = len(result.resolved_ips) - max_ips
        parts.append(", ".join(result.resolved_ips[:max_ips]) + (f" +{extra}" if extra > 0 else ""))
    if result.ede_codes:
        parts.append("EDE " + ",".join(map(str, result.ede_codes)))
    return " · ".join(parts) or "-"


def _fraction(passed: int, total: int) -> str:
    return f"{passed}/{total}"


def _outcome_cell(group: ProbeGroup, lang: Lang) -> Text:
    label = outcome_label(group.outcome, lang)
    if group.runs > 1:
        label += f" {group.passes}/{group.runs}"
    return Text(label, style=OUTCOME_STYLES[group.outcome])


def render_detailed_report(
    results: Sequence[ProbeResult],
    summary: TargetSummary,
    lang: Lang | str = Lang.EN,
    console: Console | None = None,
    hints: Sequence[Hint] = (),
) -> None:
    console = console or Console()
    lang = Lang(lang)
    title = Text.assemble(
        "🛡️ ",
        (t("report_title", lang), "bold"),
        f" — {summary.target_name} [{summary.server_endpoint} / {summary.protocol.value.upper()}]",
    )

    details = Table(title=title, header_style="bold cyan")
    details.add_column(t("col_app", lang), style="bold")
    details.add_column(t("col_domain", lang))
    details.add_column(t("col_category", lang), style="dim")
    details.add_column(t("col_expected", lang))
    details.add_column(t("col_verdict", lang))
    details.add_column(t("col_answer", lang), style="dim")
    details.add_column(t("col_latency", lang), justify="right")
    details.add_column(t("col_result", lang), justify="center")

    for group in group_results(results):
        first = group.first
        details.add_row(
            Text(first.app_name_ar if lang == Lang.AR else first.app_name),
            Text(display_domain(first)),
            Text(category_label(first.category, lang)),
            Text(expected_label(first.expected, lang)),
            Text(verdict_label(group.verdict, lang), style=verdict_style(group.verdict)),
            Text(answer_summary(group.latest_answer)),
            Text(format_ms(group.median_latency_ms, lang)),
            _outcome_cell(group, lang),
        )
    console.print(details)
    console.print()

    scorecard = Table(title=Text("📊 " + t("scorecard_title", lang)), header_style="bold magenta")
    scorecard.add_column(t("col_app", lang))
    for key in ("col_probes", "col_blocked", "col_safesearch", "col_allowed", "col_errors"):
        scorecard.add_column(t(key, lang), justify="right")
    scorecard.add_column(t("col_avg_latency", lang), justify="right")
    scorecard.add_column(t("col_score", lang), justify="right")

    for items in results_by_app(results).values():
        first = items[0]
        blocked = tally(items, ExpectedAction.BLOCK)
        safesearch = tally(items, ExpectedAction.SAFESEARCH)
        allowed = tally(items, ExpectedAction.ALLOW)
        passed = sum(i.outcome == Outcome.PASS for i in items)
        judged = sum(i.outcome != Outcome.INCONCLUSIVE for i in items)
        score = percent(passed, judged)
        latencies = answered_latencies(items)
        avg = sum(latencies) / len(latencies) if latencies else None
        scorecard.add_row(
            Text(first.app_name_ar if lang == Lang.AR else first.app_name),
            str(len(items)),
            _fraction(blocked.passed, blocked.conclusive),
            _fraction(safesearch.passed, safesearch.conclusive),
            _fraction(allowed.passed, allowed.conclusive),
            str(sum(i.outcome == Outcome.ERROR for i in items)),
            format_ms(avg, lang),
            Text(format_rate(score, lang), style=f"bold {score_style(score)}"),
        )
    console.print(scorecard)

    kpis = Text.assemble(
        (f"{t('kpi_compliance', lang)}: ", "bold"),
        (
            format_rate(summary.compliance_score, lang),
            f"bold {score_style(summary.compliance_score)}",
        ),
        "   ",
        (f"{t('kpi_block', lang)}: ", "bold"),
        (format_rate(summary.block_rate, lang), "green"),
        "   ",
        (f"{t('kpi_safesearch', lang)}: ", "bold"),
        (format_rate(summary.safesearch_rate, lang), "cyan"),
        "   ",
        (f"{t('kpi_false_positives', lang)}: ", "bold"),
        (
            format_rate(summary.false_positive_rate, lang),
            "green" if not summary.false_positive_rate else "bold red",
        ),
    )
    counts = Text(
        t(
            "label_probes_summary",
            lang,
            passed=summary.passed_probes,
            failed=summary.failed_probes,
            errors=summary.error_probes,
            inconclusive=summary.inconclusive_probes,
        ),
        style="dim",
    )
    latency = Text(
        f"{t('kpi_latency', lang)}: {format_ms(summary.p50_ms, lang)} | "
        f"{format_ms(summary.p95_ms, lang)} | {format_ms(summary.p99_ms, lang)}",
        style="dim",
    )
    console.print(Panel(Group(kpis, counts, latency), title=t("summary_title", lang), expand=False))
    render_hints(hints, lang, console)


def render_hints(hints: Sequence[Hint], lang: Lang | str, console: Console) -> None:
    for hint in hints:
        console.print(Text("• " + t(f"hint_{hint.key}", lang, **hint.params), style="yellow"))


def render_comparison_table(
    summaries: Sequence[TargetSummary],
    lang: Lang | str = Lang.EN,
    console: Console | None = None,
) -> None:
    console = console or Console()
    lang = Lang(lang)
    table = Table(title=Text("🏆 " + t("compare_title", lang)), header_style="bold cyan")
    table.add_column(t("col_target", lang), style="bold")
    table.add_column(t("col_endpoint", lang))
    table.add_column(t("col_protocol", lang), justify="center")
    for key in ("kpi_compliance", "kpi_block", "kpi_safesearch", "kpi_false_positives"):
        table.add_column(t(key, lang), justify="right")
    table.add_column(t("kpi_errors", lang), justify="right")
    table.add_column(t("col_p50_p95", lang), justify="right")

    ranked = sorted(
        summaries,
        key=lambda s: s.compliance_score if s.compliance_score is not None else -1.0,
        reverse=True,
    )
    for s in ranked:
        table.add_row(
            Text(s.target_name),
            Text(s.server_endpoint),
            s.protocol.value.upper(),
            Text(
                format_rate(s.compliance_score, lang),
                style=f"bold {score_style(s.compliance_score)}",
            ),
            format_rate(s.block_rate, lang),
            format_rate(s.safesearch_rate, lang),
            Text(
                format_rate(s.false_positive_rate, lang),
                style="green" if not s.false_positive_rate else "bold red",
            ),
            Text(f"{s.error_rate:.1f}%", style="green" if not s.error_probes else "bold red"),
            f"{format_ms(s.p50_ms, lang)} / {format_ms(s.p95_ms, lang)}",
        )
    console.print(table)


def _report_metadata() -> dict[str, str]:
    return {
        "tool": "sinko-probe",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def export_json(
    results: Sequence[ProbeResult],
    summary: TargetSummary,
    path: Path,
    hints: Sequence[Hint] = (),
) -> None:
    payload = {
        **_report_metadata(),
        "summary": summary.model_dump(mode="json"),
        "hints": [{"key": h.key, "params": h.params} for h in hints],
        "results": [r.model_dump(mode="json") for r in results],
    }
    _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False))


def export_comparison_json(summaries: Sequence[TargetSummary], path: Path) -> None:
    payload = {**_report_metadata(), "summaries": [s.model_dump(mode="json") for s in summaries]}
    _write_text(path, json.dumps(payload, indent=2, ensure_ascii=False))


def export_csv(results: Sequence[ProbeResult], path: Path) -> None:
    fieldnames = [*ProbeResult.model_fields, *ProbeResult.model_computed_fields]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = result.model_dump(mode="json")
            for key in ("resolved_ips", "cname_chain", "ede_codes"):
                row[key] = ";".join(map(str, row[key]))
            writer.writerow(row)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
