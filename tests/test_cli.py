import json
from pathlib import Path

import pytest
from fakedns import FakeDNSServer, answer, free_port
from typer.testing import CliRunner

from sinko_probe import __version__
from sinko_probe.cli import EXIT_BELOW_MIN_SCORE, EXIT_UNREACHABLE, app

HOMEWORK_POLICY = Path(__file__).resolve().parents[1] / "configs" / "sinko-homework-policy.yaml"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner(
        env={"COLUMNS": "220", "SINKO_TELEGRAM_TOKEN": None, "SINKO_TELEGRAM_CHAT_ID": None}
    )


def run(runner: CliRunner, *args: str):
    return runner.invoke(app, list(args), catch_exceptions=False)


def test_version(runner):
    outcome = run(runner, "--version")
    assert outcome.exit_code == 0
    assert __version__ in outcome.output


def test_list_profiles(runner):
    outcome = run(runner, "list-profiles")
    assert outcome.exit_code == 0
    assert "ai_chatbots" in outcome.output and "sinko_safesearch" in outcome.output


def test_run_against_a_perfect_sinko_writes_every_report(runner, perfect_sinko, tmp_path):
    html, report, table = tmp_path / "audit.html", tmp_path / "audit.json", tmp_path / "audit.csv"
    outcome = run(
        runner,
        "run",
        "--server",
        f"127.0.0.1:{perfect_sinko.port}",
        "--no-jitter",
        "--min-score",
        "100",
        "--html",
        str(html),
        "--json",
        str(report),
        "--csv",
        str(table),
    )
    assert outcome.exit_code == 0, outcome.output
    summary = json.loads(report.read_text(encoding="utf-8"))["summary"]
    assert summary["compliance_score"] == 100.0
    assert summary["server_endpoint"] == f"udp://127.0.0.1:{perfect_sinko.port}"
    assert "<!DOCTYPE html>" in html.read_text(encoding="utf-8")
    assert table.read_text(encoding="utf-8").count("\n") == summary["total_probes"] + 1


def test_min_score_failure_exit_code(runner, perfect_sinko: FakeDNSServer):
    perfect_sinko.set("www.wikipedia.org", answer("0.0.0.0"))  # over-blocking
    outcome = run(
        runner,
        "run",
        "-s",
        f"127.0.0.1:{perfect_sinko.port}",
        "--no-jitter",
        "--app",
        "sinko_family_shield",
        "--min-score",
        "95",
    )
    assert outcome.exit_code == EXIT_BELOW_MIN_SCORE
    assert "below the required 95.0%" in outcome.output


def test_unreachable_resolver_exit_code(runner):
    outcome = run(
        runner,
        "run",
        "-s",
        f"127.0.0.1:{free_port()}",
        "--proto",
        "tcp",
        "--timeout",
        "0.5",
        "--no-jitter",
        "--app",
        "sinko_safesearch",
    )
    assert outcome.exit_code == EXIT_UNREACHABLE
    assert "No usable answers" in outcome.output


def test_homework_policy_probes_custom_domains(runner, perfect_sinko, tmp_path):
    report = tmp_path / "audit.json"
    outcome = run(
        runner,
        "run",
        "-s",
        f"127.0.0.1:{perfect_sinko.port}",
        "--no-jitter",
        "--policy",
        str(HOMEWORK_POLICY),
        "--json",
        str(report),
    )
    payload = json.loads(report.read_text(encoding="utf-8"))
    results = {r["domain"]: r for r in payload["results"]}
    assert results["chat.roblox.com"]["expected"] == "block"
    assert results["gemini.google.com"]["expected"] == "block"
    # The perfect zone allows AI chatbots, so Homework Mode catches them.
    assert results["gemini.google.com"]["outcome"] == "fail"
    assert payload["summary"]["policy_name"].startswith("Sinko Afternoon Homework Mode")
    assert outcome.exit_code == 0


def test_arabic_report(runner, perfect_sinko):
    outcome = run(
        runner, "run", "-s", f"127.0.0.1:{perfect_sinko.port}", "--no-jitter", "--lang", "ar"
    )
    assert outcome.exit_code == 0
    assert "درجة الامتثال" in outcome.output


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["run", "--app", "nope"], "unknown profile nope"),
        (["run", "--server", "ftp://1.1.1.1"], "unknown scheme"),
        (["run", "--server", "[::1"], "malformed"),
        (["run", "--sinkhole-ip", "not-an-ip"], "invalid sinkhole"),
        (["run", "--lang", "fr"], "'fr' is not one of"),
        (["compare", "-t", "NoEquals"], "Name=address"),
    ],
)
def test_usage_errors_exit_2(runner, args, message):
    outcome = runner.invoke(app, args)
    assert outcome.exit_code == 2
    assert message in " ".join(outcome.output.split())


def test_bad_policy_file_is_a_usage_error(runner, tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("custom_blocklst: [x.com]\n", encoding="utf-8")
    outcome = runner.invoke(app, ["run", "--policy", str(policy)])
    assert outcome.exit_code == 2
    assert "custom_blocklst" in outcome.output


def test_custom_profiles_file(runner, fake_dns: FakeDNSServer, tmp_path):
    fake_dns.set("tracker.example", answer("0.0.0.0"))
    config = tmp_path / "profiles.yaml"
    config.write_text(
        "profiles:\n"
        "  - id: home_iot\n"
        "    name: Home IoT\n"
        "    probes:\n"
        "      - {domain: tracker.example, category: telemetry}\n",
        encoding="utf-8",
    )
    outcome = run(
        runner,
        "run",
        "-s",
        f"127.0.0.1:{fake_dns.port}",
        "--no-jitter",
        "--config",
        str(config),
        "--app",
        "home_iot",
        "--min-score",
        "100",
    )
    assert outcome.exit_code == 0, outcome.output
    assert "tracker.example" in outcome.output


def test_compare_mixes_transports_and_ranks_targets(runner, perfect_sinko, tmp_path):
    leaky = FakeDNSServer(default=answer("198.51.100.99")).start()  # blocks nothing
    report = tmp_path / "compare.json"
    try:
        outcome = run(
            runner,
            "compare",
            "-t",
            f"Sinko=udp://127.0.0.1:{perfect_sinko.port}",
            "-t",
            f"Leaky=tcp://127.0.0.1:{leaky.port}",
            "--app",
            "sinko_family_shield",
            "--json",
            str(report),
        )
    finally:
        leaky.stop()
    assert outcome.exit_code == 0, outcome.output
    summaries = json.loads(report.read_text(encoding="utf-8"))["summaries"]
    assert [s["target_name"] for s in summaries] == ["Sinko", "Leaky"]
    assert summaries[0]["protocol"] == "udp" and summaries[1]["protocol"] == "tcp"
    assert outcome.output.index("Sinko") < outcome.output.index("Leaky")


def test_compare_accepts_doh_urls_and_ipv6(runner):
    """'Name=https://...' and 'Name=2606:...' used to crash with int() on the URL/address."""
    outcome = run(
        runner,
        "compare",
        "-t",
        f"DoH=https://127.0.0.1:{free_port()}/dns-query",
        "-t",
        f"V6=[::1]:{free_port()}",
        "--app",
        "sinko_safesearch",
        "--timeout",
        "0.5",
    )
    assert outcome.exit_code == EXIT_UNREACHABLE
    assert "https://127.0.0.1" in outcome.output


def test_telegram_needs_both_settings(runner, perfect_sinko):
    outcome = run(
        runner,
        "run",
        "-s",
        f"127.0.0.1:{perfect_sinko.port}",
        "--no-jitter",
        "--app",
        "sinko_safesearch",
        "--telegram-token",
        "123:abc",
    )
    assert "needs both" in outcome.output
