import asyncio
import os
from pathlib import Path
from typing import List, Optional
import typer
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from .engine import DNSSimulatorEngine
from .html_report import export_html_dashboard
from .models import AppProfile, SinkoPolicyConfig, TransportProtocol
from .notifier import send_telegram_summary
from .profiles import BUILTIN_PROFILES
from .reporter import (
    export_csv,
    export_json,
    render_comparison_table,
    render_detailed_report,
)

app = typer.Typer(
    name="sinko-probe",
    help="State-of-the-art multi-protocol DNS traffic simulator & benchmark suite for Sinko and DNS ad-blockers.",
    add_completion=False,
)
console = Console()


@app.command("list-profiles")
def list_profiles() -> None:
    """List all built-in bilingual application simulation profiles."""
    for profile_id, prof in BUILTIN_PROFILES.items():
        console.print(
            f"[bold cyan]{profile_id}[/] — [bold]{prof.name}[/] / [magenta]{prof.name_ar}[/] "
            f"({len(prof.probes)} probes)"
        )
        console.print(f"  [dim]{prof.description}[/]")


@app.command("run")
def run_simulation(
    server: str = typer.Option("127.0.0.1", "--server", "-s", help="Target DNS IP or DoH URL"),
    name: str = typer.Option("Sinko", "--name", "-n", help="Friendly name for the target appliance"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Custom DNS port (default: auto by protocol)"),
    protocol: TransportProtocol = typer.Option(TransportProtocol.UDP, "--proto", help="Transport: udp, tcp, dot, doh"),
    apps: Optional[List[str]] = typer.Option(None, "--app", "-a", help="Specific app profile IDs to simulate"),
    policy_file: Optional[Path] = typer.Option(None, "--policy", help="Sinko policy YAML to override category rules"),
    custom_yaml: Optional[Path] = typer.Option(None, "--config", "-c", help="Custom YAML app profiles"),
    iterations: int = typer.Option(1, "--iterations", "-i", help="Number of simulation waves"),
    concurrency: int = typer.Option(50, "--concurrency", help="Max concurrent DNS requests"),
    timeout: float = typer.Option(3.5, "--timeout", help="Query timeout in seconds"),
    sinkhole_ip: Optional[List[str]] = typer.Option(None, "--sinkhole-ip", help="Custom Sinko block-page VIPs"),
    no_jitter: bool = typer.Option(False, "--no-jitter", help="Disable realistic inter-packet burst jitter"),
    cache_bust: bool = typer.Option(False, "--cache-bust", help="Prepend random subdomains to test wildcard rules"),
    lang: str = typer.Option("en", "--lang", help="Report language: 'en' or 'ar'"),
    html_out: Optional[Path] = typer.Option(None, "--html", help="Export standalone dark-mode HTML dashboard"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Export JSON report"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export CSV report"),
    telegram_token: Optional[str] = typer.Option(
        lambda: os.environ.get("SINKO_TELEGRAM_TOKEN"),
        "--telegram-token",
        help="Telegram Bot token (or set SINKO_TELEGRAM_TOKEN)",
    ),
    telegram_chat_id: Optional[str] = typer.Option(
        lambda: os.environ.get("SINKO_TELEGRAM_CHAT_ID"),
        "--telegram-chat-id",
        help="Telegram Chat ID (or set SINKO_TELEGRAM_CHAT_ID)",
    ),
    min_score: float = typer.Option(0.0, "--min-score", help="Minimum compliance score for exit code 0"),
) -> None:
    """Audit a Sinko appliance or DNS ad-blocker with realistic multi-app traffic."""
    profiles_map = dict(BUILTIN_PROFILES)
    if custom_yaml:
        raw = yaml.safe_load(custom_yaml.read_text(encoding="utf-8"))
        for item in raw.get("profiles", []):
            prof = AppProfile.model_validate(item)
            profiles_map[prof.id] = prof

    selected_profiles = (
        [profiles_map[a] for a in apps if a in profiles_map]
        if apps
        else list(profiles_map.values())
    )

    policy = None
    if policy_file:
        policy = SinkoPolicyConfig.model_validate(
            yaml.safe_load(policy_file.read_text(encoding="utf-8"))
        )

    engine = DNSSimulatorEngine(
        target_name=name,
        nameserver=server,
        port=port,
        protocol=protocol,
        timeout=timeout,
        concurrency=concurrency,
        custom_sinkhole_ips=set(sinkhole_ip) if sinkhole_ip else set(),
        cache_bust=cache_bust,
        realistic_jitter=not no_jitter,
        policy=policy,
    )

    total_queries = sum(len(p.probes) for p in selected_profiles) * iterations

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(
            f"Simulating {len(selected_profiles)} apps against {name} ({server})...",
            total=total_queries,
        )
        results = asyncio.run(
            engine.run_simulation(
                selected_profiles,
                iterations=iterations,
                on_complete=lambda _: progress.advance(task_id),
            )
        )

    summary = engine.summarize(results)
    render_detailed_report(results, summary, lang=lang)

    if html_out:
        export_html_dashboard(results, summary, html_out)
        console.print(f"[bold green]✔ HTML interactive dashboard saved:[/] {html_out}")
    if json_out:
        export_json(results, summary, json_out)
    if csv_out:
        export_csv(results, csv_out)
    if telegram_token and telegram_chat_id:
        send_telegram_summary(telegram_token, telegram_chat_id, summary)

    if min_score > 0 and summary.compliance_score < min_score:
        console.print(
            f"[bold red]✘ Compliance score {summary.compliance_score:.1f}% is below required {min_score:.1f}%[/]"
        )
        raise typer.Exit(code=2)


@app.command("compare")
def compare_resolvers(
    targets: List[str] = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target spec in format 'Name=IP[:Port]' (e.g. -t Sinko=192.168.1.2 -t CloudflareFamily=1.1.1.3)",
    ),
    protocol: TransportProtocol = typer.Option(TransportProtocol.UDP, "--proto", help="Transport protocol"),
    policy_file: Optional[Path] = typer.Option(None, "--policy", help="Sinko policy YAML"),
) -> None:
    """Benchmark Sinko head-to-head against other DNS resolvers (e.g., Pi-hole, 1.1.1.3, Quad9)."""
    profiles = list(BUILTIN_PROFILES.values())
    policy = (
        SinkoPolicyConfig.model_validate(yaml.safe_load(policy_file.read_text(encoding="utf-8")))
        if policy_file
        else None
    )
    summaries = []

    for spec in targets:
        if "=" not in spec:
            console.print(f"[bold red]Invalid target format '{spec}'. Use Name=IP[/]")
            raise typer.Exit(code=1)
        t_name, endpoint = spec.split("=", 1)
        host, port_str = (endpoint.split(":", 1) + [None])[:2]
        port = int(port_str) if port_str else None

        engine = DNSSimulatorEngine(
            target_name=t_name,
            nameserver=host,
            port=port,
            protocol=protocol,
            realistic_jitter=False,
            policy=policy,
        )
        console.print(f"[cyan]⚡ Benchmarking [bold]{t_name}[/] ({endpoint})...[/]")
        res = asyncio.run(engine.run_simulation(profiles))
        summaries.append(engine.summarize(res))

    console.print()
    render_comparison_table(summaries)


if __name__ == "__main__":
    app()
