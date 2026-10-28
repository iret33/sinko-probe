import httpx
from rich.console import Console
from .models import TargetSummary

console = Console()


def send_telegram_summary(
    bot_token: str, chat_id: str, summary: TargetSummary
) -> None:
    status_icon = "✅" if summary.compliance_score >= 90 else "⚠️"
    text = (
        f"{status_icon} *Sinko-Probe DNS Audit Report*\n"
        f"• *Target:* `{summary.target_name}` (`{summary.server_endpoint}`)\n"
        f"• *Protocol:* `{summary.protocol.value.upper()}`\n"
        f"• *Compliance Score:* *{summary.compliance_score:.1f}%* ({summary.passed_probes}/{summary.total_probes})\n"
        f"• *Block Efficacy:* `{summary.block_rate:.1f}%`\n"
        f"• *SafeSearch Enforcement:* `{summary.safesearch_rate:.1f}%`\n"
        f"• *False Positives:* `{summary.false_positive_rate:.1f}%`\n"
        f"• *Latency (p50 / p95):* `{summary.p50_ms} ms / {summary.p95_ms} ms`"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = httpx.post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=10.0,
        )
        resp.raise_for_status()
        console.print("[bold green]✔ Telegram report delivered successfully.[/]")
    except Exception as exc:
        console.print(f"[bold red]✘ Failed to send Telegram notification:[/] {exc}")
