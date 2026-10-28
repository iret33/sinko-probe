import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import ExpectedAction, ProbeResult, TargetSummary, Verdict

console = Console()


def render_detailed_report(
    results: List[ProbeResult], summary: TargetSummary, lang: str = "en"
) -> None:
    title = (
        f"🛡️ تقرير فحص سينكو (Sinko-Probe) — {summary.target_name} [{summary.server_endpoint}]"
        if lang == "ar"
        else f"🛡️ Sinko-Probe Audit Report — {summary.target_name} [{summary.server_endpoint} / {summary.protocol.value.upper()}]"
    )

    detail_table = Table(title=title, header_style="bold cyan", show_lines=False)
    detail_table.add_column("App Profile" if lang == "en" else "التطبيق", style="bold")
    detail_table.add_column("Domain" if lang == "en" else "النطاق")
    detail_table.add_column("Category" if lang == "en" else "الفئة", style="dim")
    detail_table.add_column("Expected" if lang == "en" else "المتوقع")
    detail_table.add_column("Verdict" if lang == "en" else "النتيجة")
    detail_table.add_column("CNAME / IP", style="dim")
    detail_table.add_column("Latency", justify="right")
    detail_table.add_column("Audit" if lang == "en" else "التقييم", justify="center")

    for r in results:
        if "BLOCKED" in r.verdict.value or r.verdict == Verdict.SAFESEARCH_ENFORCED:
            v_style = "green"
        elif r.verdict == Verdict.ERROR_TIMEOUT:
            v_style = "bold red"
        else:
            v_style = "yellow"

        badge = "[bold green]PASS[/]" if r.passed_expectation else "[bold red]FAIL[/]"
        target_info = (
            f"CNAME: {r.cname_chain[0]}"
            if r.cname_chain
            else (", ".join(r.resolved_ips[:2]) if r.resolved_ips else "-")
        )
        app_label = r.app_name_ar if lang == "ar" else r.app_name

        detail_table.add_row(
            app_label,
            r.domain,
            r.category.value,
            r.expected.value.upper(),
            f"[{v_style}]{r.verdict.value}[/]",
            target_info,
            f"{r.latency_ms:.1f} ms",
            badge,
        )

    console.print(detail_table)
    console.print()

    app_table = Table(
        title="📊 Application Protection Scorecard" if lang == "en" else "📊 بطاقة أداء حماية التطبيقات",
        header_style="bold magenta",
    )
    app_table.add_column("Application" if lang == "en" else "التطبيق")
    app_table.add_column("Probes", justify="right")
    app_table.add_column("Blocked", justify="right")
    app_table.add_column("SafeSearch", justify="right")
    app_table.add_column("Core Allowed", justify="right")
    app_table.add_column("Avg Latency", justify="right")
    app_table.add_column("Score", justify="right")

    grouped = defaultdict(list)
    for r in results:
        key = r.app_name_ar if lang == "ar" else r.app_name
        grouped[key].append(r)

    for app_label, items in grouped.items():
        total = len(items)
        exp_b = [i for i in items if i.expected == ExpectedAction.BLOCK]
        act_b = [i for i in exp_b if i.passed_expectation]

        exp_ss = [i for i in items if i.expected == ExpectedAction.SAFESEARCH]
        act_ss = [i for i in exp_ss if i.passed_expectation]

        exp_a = [i for i in items if i.expected == ExpectedAction.ALLOW]
        act_a = [i for i in exp_a if i.passed_expectation]

        passed = sum(1 for i in items if i.passed_expectation)
        pct = (passed / total) * 100 if total else 0.0
        avg_lat = sum(i.latency_ms for i in items) / total if total else 0.0
        color = "green" if pct >= 85 else ("yellow" if pct >= 60 else "red")

        app_table.add_row(
            app_label,
            str(total),
            f"{len(act_b)}/{len(exp_b)}",
            f"{len(act_ss)}/{len(exp_ss)}",
            f"{len(act_a)}/{len(exp_a)}",
            f"{avg_lat:.1f} ms",
            f"[bold {color}]{pct:.1f}%[/]",
        )

    console.print(app_table)
    console.print(
        Panel(
            f"[bold]Compliance Score:[/] [bold cyan]{summary.compliance_score:.1f}%[/]   "
            f"[bold]Block Efficacy:[/] [green]{summary.block_rate:.1f}%[/]   "
            f"[bold]SafeSearch:[/] [cyan]{summary.safesearch_rate:.1f}%[/]   "
            f"[bold]False Positives:[/] [yellow]{summary.false_positive_rate:.1f}%[/]\n"
            f"[dim]Latency Percentiles — p50: {summary.p50_ms} ms | p95: {summary.p95_ms} ms | p99: {summary.p99_ms} ms[/]",
            title="Sinko Telemetry Summary",
            expand=False,
        )
    )


def render_comparison_table(summaries: List[TargetSummary]) -> None:
    comp_table = Table(
        title="🏆 Head-to-Head DNS Resolver & Parental Control Benchmark",
        header_style="bold cyan",
    )
    comp_table.add_column("Resolver Target", style="bold")
    comp_table.add_column("Endpoint")
    comp_table.add_column("Protocol", justify="center")
    comp_table.add_column("Overall Score", justify="right")
    comp_table.add_column("Block Efficacy", justify="right")
    comp_table.add_column("SafeSearch", justify="right")
    comp_table.add_column("False Positives", justify="right")
    comp_table.add_column("p50 / p95 Latency", justify="right")

    for s in sorted(summaries, key=lambda x: x.compliance_score, reverse=True):
        color = "green" if s.compliance_score >= 85 else ("yellow" if s.compliance_score >= 60 else "red")
        fp_color = "green" if s.false_positive_rate == 0 else "bold red"
        comp_table.add_row(
            s.target_name,
            s.server_endpoint,
            s.protocol.value.upper(),
            f"[bold {color}]{s.compliance_score:.1f}%[/]",
            f"{s.block_rate:.1f}%",
            f"{s.safesearch_rate:.1f}%",
            f"[{fp_color}]{s.false_positive_rate:.1f}%[/]",
            f"{s.p50_ms} / {s.p95_ms} ms",
        )
    console.print(comp_table)


def export_json(results: List[ProbeResult], summary: TargetSummary, path: Path) -> None:
    payload = {
        "summary": summary.model_dump(mode="json"),
        "results": [r.model_dump(mode="json") for r in results],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"[bold green]✔ JSON report saved:[/] {path}")


def export_csv(results: List[ProbeResult], path: Path) -> None:
    if not results:
        return
    fieldnames = list(results[0].model_dump(mode="json").keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = r.model_dump(mode="json")
            row["resolved_ips"] = ";".join(row["resolved_ips"])
            row["cname_chain"] = ";".join(row["cname_chain"])
            writer.writerow(row)
    console.print(f"[bold green]✔ CSV report saved:[/] {path}")
