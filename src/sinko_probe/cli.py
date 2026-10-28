"""Command line interface.

Exit codes: 0 success, 1 compliance below ``--min-score``, 2 invalid usage or configuration,
3 the resolver could not be reached at all.
"""

import asyncio
import ssl
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Annotated

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text

from . import __version__
from .analysis import find_hints
from .classify import parse_sinkholes
from .endpoints import EndpointError
from .engine import DNSSimulatorEngine, PlanError, PlannedProbe
from .html_report import export_html_dashboard
from .i18n import Lang, t
from .models import AppProfile, ProbeResult, SinkoPolicyConfig, TransportProtocol
from .notifier import NotificationError, send_telegram_summary
from .profiles import BUILTIN_PROFILES
from .reporter import (
    export_comparison_json,
    export_csv,
    export_json,
    render_comparison_table,
    render_detailed_report,
)

EXIT_BELOW_MIN_SCORE = 1
EXIT_UNREACHABLE = 3

app = typer.Typer(
    name="sinko-probe",
    help="Multi-protocol DNS traffic simulator, SafeSearch auditor and benchmark suite for Sinko "
    "and other DNS filters.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"sinko-probe {__version__}")
        raise typer.Exit


ProtocolOption = Annotated[
    TransportProtocol,
    typer.Option("--proto", case_sensitive=False, help="Transport for addresses without a scheme."),
]
AppsOption = Annotated[
    list[str] | None,
    typer.Option("--app", "-a", help="App profile ID to simulate (repeatable). Default: all."),
]
PolicyOption = Annotated[
    Path | None,
    typer.Option(
        "--policy",
        exists=True,
        dir_okay=False,
        help="Sinko policy YAML (e.g. Homework Mode) that overrides the expectations.",
    ),
]
ConfigOption = Annotated[
    Path | None,
    typer.Option(
        "--config",
        "-c",
        exists=True,
        dir_okay=False,
        help="YAML file with extra app profiles under a top-level 'profiles:' list.",
    ),
]
IterationsOption = Annotated[
    int, typer.Option("--iterations", "-i", min=1, help="Query waves, sent one after another.")
]
ConcurrencyOption = Annotated[
    int, typer.Option("--concurrency", min=1, help="Max queries in flight.")
]
TimeoutOption = Annotated[
    float, typer.Option("--timeout", min=0.1, help="Per-query timeout in seconds.")
]
SinkholeOption = Annotated[
    list[str] | None,
    typer.Option(
        "--sinkhole-ip", help="Block-page IP or CIDR that counts as blocked (repeatable)."
    ),
]
CacheBustOption = Annotated[
    bool,
    typer.Option(
        "--cache-bust",
        help="Query a random subdomain of every must-block domain to test wildcard rules.",
    ),
]
InsecureOption = Annotated[
    bool, typer.Option("--insecure", help="Do not verify DoT/DoH server certificates.")
]
CaFileOption = Annotated[
    Path | None,
    typer.Option(
        "--ca-file",
        exists=True,
        dir_okay=False,
        help="Verify DoT/DoH certificates against this CA bundle (e.g. your Sinko box's CA).",
    ),
]
LangOption = Annotated[Lang, typer.Option("--lang", case_sensitive=False, help="Report language.")]
JsonOption = Annotated[
    Path | None, typer.Option("--json", dir_okay=False, help="Write a JSON report.")
]


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Multi-protocol DNS traffic simulator, SafeSearch auditor and benchmark suite."""


@app.command("list-profiles")
def list_profiles(custom_yaml: ConfigOption = None) -> None:
    """List the bilingual application simulation profiles."""
    for profile_id, profile in _load_profiles(custom_yaml).items():
        line = Text.assemble(
            (profile_id, "bold cyan"),
            " — ",
            (profile.name, "bold"),
            " / ",
            (profile.name_ar or profile.name, "magenta"),
            f" ({len(profile.probes)} probes)",
        )
        console.print(line)
        console.print(Text(f"  {profile.description}", style="dim"))


@app.command("run")
def run_command(
    server: Annotated[
        str,
        typer.Option(
            "--server",
            "-s",
            help="Resolver: IP, IP:port, [IPv6]:port, hostname, tcp://, tls:// or a DoH URL.",
        ),
    ] = "127.0.0.1",
    name: Annotated[
        str, typer.Option("--name", "-n", help="Friendly name for the target.")
    ] = "Sinko",
    port: Annotated[
        int | None,
        typer.Option("--port", "-p", min=1, max=65535, help="Port (default: by protocol)."),
    ] = None,
    protocol: ProtocolOption = TransportProtocol.UDP,
    apps: AppsOption = None,
    policy_file: PolicyOption = None,
    custom_yaml: ConfigOption = None,
    iterations: IterationsOption = 1,
    concurrency: ConcurrencyOption = 50,
    timeout: TimeoutOption = 3.5,
    sinkhole_ip: SinkholeOption = None,
    no_jitter: Annotated[
        bool, typer.Option("--no-jitter", help="Send all queries at once instead of app bursts.")
    ] = False,
    cache_bust: CacheBustOption = False,
    insecure: InsecureOption = False,
    ca_file: CaFileOption = None,
    tls_server_name: Annotated[
        str | None,
        typer.Option(
            "--tls-server-name", help="Certificate name to verify when DoT targets an IP."
        ),
    ] = None,
    lang: LangOption = Lang.EN,
    html_out: Annotated[
        Path | None,
        typer.Option("--html", dir_okay=False, help="Write a standalone HTML dashboard."),
    ] = None,
    json_out: JsonOption = None,
    csv_out: Annotated[
        Path | None, typer.Option("--csv", dir_okay=False, help="Write a CSV report.")
    ] = None,
    telegram_token: Annotated[
        str | None,
        typer.Option("--telegram-token", envvar="SINKO_TELEGRAM_TOKEN", help="Telegram bot token."),
    ] = None,
    telegram_chat_id: Annotated[
        str | None,
        typer.Option(
            "--telegram-chat-id", envvar="SINKO_TELEGRAM_CHAT_ID", help="Telegram chat ID."
        ),
    ] = None,
    min_score: Annotated[
        float,
        typer.Option(
            "--min-score", min=0, max=100, help="Exit with code 1 below this compliance score."
        ),
    ] = 0.0,
) -> None:
    """Audit a Sinko appliance or DNS filter with realistic multi-app traffic."""
    _check_ca_file(ca_file)
    _check_sinkholes(sinkhole_ip)
    profiles = _select_profiles(apps, custom_yaml)
    policy = _load_policy(policy_file)
    engine = _make_engine(
        name,
        server,
        "--server",
        port=port,
        protocol=protocol,
        timeout=timeout,
        concurrency=concurrency,
        custom_sinkhole_ips=sinkhole_ip,
        cache_bust=cache_bust,
        realistic_jitter=not no_jitter,
        policy=policy,
        insecure=insecure,
        ca_file=ca_file,
        tls_server_name=tls_server_name,
    )
    plan = _build_plan(engine, profiles)
    endpoint = engine.endpoint.display()
    description = t(
        "simulating", lang, apps=len({p.profile.id for p in plan}), target=name, endpoint=endpoint
    )
    results = _execute(engine, plan, iterations, description)
    summary = engine.summarize(results)
    hints = find_hints(results)
    render_detailed_report(results, summary, lang=lang, console=console, hints=hints)

    if html_out:
        _export(html_out, "--html", export_html_dashboard, results, summary, html_out, lang, hints)
        _saved("saved_html", html_out, lang)
    if json_out:
        _export(json_out, "--json", export_json, results, summary, json_out, hints)
        _saved("saved_json", json_out, lang)
    if csv_out:
        _export(csv_out, "--csv", export_csv, results, csv_out)
        _saved("saved_csv", csv_out, lang)
    if telegram_token and telegram_chat_id:
        try:
            send_telegram_summary(
                telegram_token, telegram_chat_id, summary, lang=lang, threshold=min_score or 90.0
            )
        except NotificationError as exc:
            _fail(f"{t('telegram_failed', lang)} {exc}")
        else:
            console.print(Text(f"✔ {t('telegram_sent', lang)}", style="bold green"))
    elif telegram_token or telegram_chat_id:
        _fail("Telegram needs both --telegram-token and --telegram-chat-id.")

    if summary.error_probes == summary.total_probes:
        _fail(t("unreachable", lang, target=name, endpoint=endpoint))
        raise typer.Exit(EXIT_UNREACHABLE)
    if min_score > 0 and (summary.compliance_score or 0.0) < min_score:
        score = (
            f"{summary.compliance_score:.1f}%" if summary.compliance_score is not None else "n/a"
        )
        _fail(t("below_min_score", lang, score=score, required=f"{min_score:.1f}"))
        raise typer.Exit(EXIT_BELOW_MIN_SCORE)


@app.command("compare")
def compare_command(
    targets: Annotated[
        list[str],
        typer.Option(
            "--target",
            "-t",
            help="Name=address (repeatable), e.g. -t Sinko=192.168.1.2 "
            "-t CloudflareFamily=tls://1.1.1.3. Addresses take the same forms as run --server.",
        ),
    ],
    protocol: ProtocolOption = TransportProtocol.UDP,
    apps: AppsOption = None,
    policy_file: PolicyOption = None,
    custom_yaml: ConfigOption = None,
    iterations: IterationsOption = 1,
    concurrency: ConcurrencyOption = 50,
    timeout: TimeoutOption = 3.5,
    sinkhole_ip: SinkholeOption = None,
    cache_bust: CacheBustOption = False,
    insecure: InsecureOption = False,
    ca_file: CaFileOption = None,
    lang: LangOption = Lang.EN,
    json_out: JsonOption = None,
) -> None:
    """Benchmark Sinko head-to-head against other resolvers (Pi-hole, 1.1.1.3, Quad9, ...)."""
    _check_ca_file(ca_file)
    _check_sinkholes(sinkhole_ip)
    profiles = _select_profiles(apps, custom_yaml)
    policy = _load_policy(policy_file)
    engines = []
    for spec in targets:
        target_name, separator, address = spec.partition("=")
        if not separator or not target_name.strip() or not address.strip():
            raise typer.BadParameter(f"{spec!r} is not in Name=address form", param_hint="--target")
        engines.append(
            _make_engine(
                target_name.strip(),
                address.strip(),
                "--target",
                protocol=protocol,
                timeout=timeout,
                concurrency=concurrency,
                custom_sinkhole_ips=sinkhole_ip,
                cache_bust=cache_bust,
                realistic_jitter=False,
                policy=policy,
                insecure=insecure,
                ca_file=ca_file,
            )
        )

    plan = _build_plan(engines[0], profiles)
    summaries = []
    unreachable = False
    for engine in engines:
        endpoint = engine.endpoint.display()
        description = t("benchmarking", lang, target=engine.target_name, endpoint=endpoint)
        results = _execute(engine, plan, iterations, description)
        summary = engine.summarize(results)
        summaries.append(summary)
        if summary.error_probes == summary.total_probes:
            _fail(t("unreachable", lang, target=engine.target_name, endpoint=endpoint))
            unreachable = True

    console.print()
    render_comparison_table(summaries, lang=lang, console=console)
    if json_out:
        _export(json_out, "--json", export_comparison_json, summaries, json_out)
        _saved("saved_json", json_out, lang)
    if unreachable:
        raise typer.Exit(EXIT_UNREACHABLE)


# -- helpers -------------------------------------------------------------------------------


def _fail(message: str) -> None:
    console.print(Text(f"✘ {message}", style="bold red"))


def _saved(key: str, path: Path, lang: Lang) -> None:
    console.print(Text.assemble((f"✔ {t(key, lang)} ", "bold green"), str(path)))


def _export(path: Path, option: str, writer: Callable[..., None], *args: object) -> None:
    try:
        writer(*args)
    except OSError as exc:
        raise typer.BadParameter(f"cannot write {path}: {exc}", param_hint=option) from None


def _read_yaml(path: Path, option: str) -> object:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise typer.BadParameter(f"cannot read {path}: {exc}", param_hint=option) from None


def _validation_message(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or 'value'}: {error['msg']}"
        for error in exc.errors()
    )


def _load_profiles(custom_yaml: Path | None) -> dict[str, AppProfile]:
    profiles = dict(BUILTIN_PROFILES)
    if custom_yaml is None:
        return profiles
    data = _read_yaml(custom_yaml, "--config")
    items = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise typer.BadParameter("expected a top-level 'profiles:' list", param_hint="--config")
    for index, item in enumerate(items, start=1):
        try:
            profile = AppProfile.model_validate(item)
        except ValidationError as exc:
            raise typer.BadParameter(
                f"profile #{index}: {_validation_message(exc)}", param_hint="--config"
            ) from None
        profiles[profile.id] = profile
    return profiles


def _select_profiles(apps: Sequence[str] | None, custom_yaml: Path | None) -> list[AppProfile]:
    available = _load_profiles(custom_yaml)
    if not apps:
        return list(available.values())
    unknown = [a for a in apps if a not in available]
    if unknown:
        raise typer.BadParameter(
            f"unknown profile {', '.join(unknown)} (available: {', '.join(available)})",
            param_hint="--app",
        )
    return [available[a] for a in dict.fromkeys(apps)]


def _load_policy(path: Path | None) -> SinkoPolicyConfig | None:
    if path is None:
        return None
    data = _read_yaml(path, "--policy")
    try:
        return SinkoPolicyConfig.model_validate(data if data is not None else {})
    except ValidationError as exc:
        raise typer.BadParameter(_validation_message(exc), param_hint="--policy") from None


def _check_sinkholes(values: Sequence[str] | None) -> None:
    try:
        parse_sinkholes(values or ())
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--sinkhole-ip") from None


def _check_ca_file(ca_file: Path | None) -> None:
    if ca_file is None:
        return
    try:
        ssl.create_default_context(cafile=str(ca_file))
    except (ssl.SSLError, OSError, ValueError) as exc:
        raise typer.BadParameter(f"not a usable CA bundle: {exc}", param_hint="--ca-file") from None


def _make_engine(name: str, address: str, option: str, **options: object) -> DNSSimulatorEngine:
    try:
        return DNSSimulatorEngine(target_name=name, nameserver=address, **options)  # type: ignore[arg-type]
    except EndpointError as exc:
        raise typer.BadParameter(str(exc), param_hint=option) from None


def _build_plan(engine: DNSSimulatorEngine, profiles: Sequence[AppProfile]) -> list[PlannedProbe]:
    try:
        return engine.build_plan(profiles)
    except PlanError as exc:
        raise typer.BadParameter(str(exc), param_hint="--policy") from None


def _execute(
    engine: DNSSimulatorEngine, plan: Sequence[PlannedProbe], iterations: int, description: str
) -> list[ProbeResult]:
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(escape(description), total=len(plan) * iterations)
        return asyncio.run(
            engine.run_plan(plan, iterations, on_complete=lambda _: progress.advance(task_id))
        )


if __name__ == "__main__":
    app()
