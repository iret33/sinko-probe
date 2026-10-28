"""Telegram summary notifications."""

import html

import httpx

from .i18n import Lang, format_ms, format_rate, t
from .models import TargetSummary

TELEGRAM_API = "https://api.telegram.org"


class NotificationError(RuntimeError):
    """Telegram rejected or never received the message. The bot token is redacted."""


def build_telegram_message(
    summary: TargetSummary, lang: Lang | str = Lang.EN, threshold: float = 90.0
) -> str:
    """Render the summary as Telegram HTML, escaping everything that came from the user."""
    if summary.total_probes and summary.error_probes == summary.total_probes:
        icon = "🚨"
    elif (summary.compliance_score or 0.0) >= threshold and not summary.error_probes:
        icon = "✅"
    else:
        icon = "⚠️"

    def esc(value: object) -> str:
        return html.escape(str(value), quote=False)

    judged = summary.total_probes - summary.inconclusive_probes
    compliance = esc(format_rate(summary.compliance_score, lang))
    target = esc(summary.target_name)
    endpoint = esc(summary.server_endpoint)
    rows = [
        (t("label_target", lang), f"<code>{target}</code> (<code>{endpoint}</code>)"),
        (t("col_protocol", lang), f"<code>{summary.protocol.value.upper()}</code>"),
    ]
    if summary.policy_name:
        rows.append((t("label_policy", lang), esc(summary.policy_name)))
    rows += [
        (t("kpi_compliance", lang), f"<b>{compliance}</b> ({summary.passed_probes}/{judged})"),
        (t("kpi_block", lang), esc(format_rate(summary.block_rate, lang))),
        (t("kpi_safesearch", lang), esc(format_rate(summary.safesearch_rate, lang))),
        (t("kpi_false_positives", lang), esc(format_rate(summary.false_positive_rate, lang))),
        (t("kpi_errors", lang), str(summary.error_probes)),
        (
            "p50 / p95",
            f"{esc(format_ms(summary.p50_ms, lang))} / {esc(format_ms(summary.p95_ms, lang))}",
        ),
    ]
    lines = [f"{icon} <b>{esc(t('telegram_title', lang))}</b>"]
    lines += [f"• <b>{esc(label)}:</b> {value}" for label, value in rows]
    return "\n".join(lines)


def send_telegram_summary(
    bot_token: str,
    chat_id: str,
    summary: TargetSummary,
    *,
    lang: Lang | str = Lang.EN,
    threshold: float = 90.0,
    client: httpx.Client | None = None,
) -> None:
    payload = {
        "chat_id": chat_id,
        "text": build_telegram_message(summary, lang, threshold),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    url = f"{TELEGRAM_API}/bot{bot_token}/sendMessage"
    try:
        if client is None:
            with httpx.Client(timeout=10.0) as own_client:
                response = own_client.post(url, json=payload)
        else:
            response = client.post(url, json=payload)
    except httpx.HTTPError as exc:
        # httpx puts the request URL, and with it the bot token, into its messages.
        raise NotificationError(_redact(str(exc) or type(exc).__name__, bot_token)) from None
    if not response.is_success:
        try:
            body = response.json()
        except ValueError:
            body = None
        reason = body.get("description", "") if isinstance(body, dict) else ""
        message = f"HTTP {response.status_code}" + (f": {reason}" if reason else "")
        raise NotificationError(_redact(message, bot_token))


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "<redacted>") if secret else text
