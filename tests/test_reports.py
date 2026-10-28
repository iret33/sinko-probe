import base64
import csv
import hashlib
import json
from html.parser import HTMLParser

import httpx
import pytest
from rich.console import Console

from sinko_probe.analysis import Hint, summarize_results
from sinko_probe.classify import outcome_for
from sinko_probe.html_report import CSP, SCRIPT, render_html
from sinko_probe.i18n import Lang
from sinko_probe.models import (
    Category,
    ExpectedAction,
    ProbeResult,
    TransportProtocol,
    Verdict,
)
from sinko_probe.notifier import NotificationError, build_telegram_message, send_telegram_summary
from sinko_probe.reporter import (
    export_csv,
    export_json,
    render_comparison_table,
    render_detailed_report,
)

XSS_NAME = '<script>alert("name")</script>'
XSS_CNAME = "<img src=x onerror=alert(1)>.evil.example"
MARKUP = "evil[/]name.example"  # crashed the old Rich report with MarkupError


def result(domain, expected, verdict, **kwargs):
    defaults = {
        "target_name": XSS_NAME,
        "app_id": "youtube_app",
        "app_name": "YouTube Mobile & Smart TV",
        "app_name_ar": "تطبيق يوتيوب",
        "record_type": "A",
        "category": Category.ADS,
        "latency_ms": 12.5,
    }
    defaults.update(kwargs)
    return ProbeResult(
        domain=domain,
        expected=expected,
        verdict=verdict,
        outcome=outcome_for(expected, verdict),
        **defaults,
    )


@pytest.fixture
def results():
    return [
        result(
            "ads.example", ExpectedAction.BLOCK, Verdict.BLOCKED_ZERO_IP, resolved_ips=["0.0.0.0"]
        ),
        result(
            "www.google.com",
            ExpectedAction.SAFESEARCH,
            Verdict.ALLOWED_RESOLVED,
            category=Category.SAFE_SEARCH,
            cname_chain=[XSS_CNAME, MARKUP],
            resolved_ips=["203.0.113.5"],
        ),
        result(
            "www.wikipedia.org",
            ExpectedAction.ALLOW,
            Verdict.ERROR_TIMEOUT,
            category=Category.CORE_SERVICE,
            error_message="no answer within 3.5s <b>",
        ),
    ]


@pytest.fixture
def summary(results):
    return summarize_results(
        results,
        target_name=XSS_NAME,
        server_endpoint="udp://[sinko.local]:53",
        protocol=TransportProtocol.UDP,
        policy_name="Homework & <Mode>",
    )


class TagBalance(HTMLParser):
    VOID = frozenset({"meta", "link", "input", "br", "wbr", "img", "circle", "path"})

    def __init__(self):
        super().__init__()
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> (open: {self.stack[-3:]})")
        else:
            self.stack.pop()


def test_html_escapes_untrusted_values(results, summary):
    page = render_html(results, summary, hints=[Hint("sinkhole", {"ip": "<x>", "count": 3})])
    assert XSS_NAME not in page
    assert "<img src=x" not in page
    assert "&lt;script&gt;alert(&quot;name&quot;)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=alert(1)&gt;.evil.example" in page
    assert "within 3.5s &lt;b&gt;" in page
    assert "Homework &amp; &lt;Mode&gt;" in page
    assert "--sinkhole-ip &lt;x&gt;" in page


def test_html_is_well_formed_and_locked_down(results, summary):
    page = render_html(results, summary)
    checker = TagBalance()
    checker.feed(page)
    assert checker.errors == []
    assert checker.stack == []
    expected_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    assert f"'sha256-{expected_hash}'" in CSP
    assert f'content="{CSP}"' in page
    assert f"<script>{SCRIPT}</script>" in page
    assert 'name="viewport"' in page
    assert "http://" not in page.replace("http://www.w3.org/2000/svg", "")  # no remote assets


def test_html_shows_na_for_untested_rates(summary):
    lone = [result("ads.example", ExpectedAction.BLOCK, Verdict.BLOCKED_NXDOMAIN)]
    page = render_html(lone, summary.model_copy(update={"safesearch_rate": None}))
    assert "n/a" in page


def test_html_arabic_is_rtl(results, summary):
    page = render_html(results, summary, lang=Lang.AR)
    assert '<html lang="ar" dir="rtl">' in page
    assert "درجة الامتثال" in page
    assert 'lang="en" dir="ltr"' in page  # English app name kept as an isolated LTR span
    assert '<code dir="ltr">ads.<wbr>example</code>' in page  # wraps between labels only
    assert '<bdi dir="ltr">12.5 ms</bdi>' in page  # not "ms 12.5" in RTL


def test_html_filters_have_counts(results, summary):
    page = render_html(results, summary)
    assert 'data-outcome="fail"' in page and 'data-outcome="error"' in page
    assert 'id="f-fail"' in page and 'id="f-all" value="all" checked' in page


def test_terminal_report_survives_markup_in_dns_data(results, summary):
    console = Console(record=True, width=200)
    render_detailed_report(results, summary, console=console, hints=[Hint("all_refused")])
    text = console.export_text()
    assert MARKUP not in text  # only the first CNAME is shown in the terminal ...
    assert XSS_CNAME in text  # ... and it is printed literally
    assert "[sinko.local]:53" in text  # used to vanish as an unknown style tag
    assert "REFUSED" in text


def test_terminal_report_in_arabic(results, summary):
    console = Console(record=True, width=200)
    render_detailed_report(results, summary, lang="ar", console=console)
    text = console.export_text()
    for label in ("التطبيق", "النطاق", "درجة الامتثال", "فعالية الحظر", "الحظر الخاطئ"):
        assert label in text


def test_comparison_table_ranks_unscored_targets_last(summary):
    console = Console(record=True, width=200)
    unscored = summary.model_copy(update={"target_name": "Down", "compliance_score": None})
    best = summary.model_copy(update={"target_name": "Best", "compliance_score": 99.0})
    render_comparison_table([unscored, best], console=console)
    text = console.export_text()
    assert text.index("Best") < text.index("Down")


def test_json_and_csv_exports(tmp_path, results, summary):
    json_path = tmp_path / "out" / "audit.json"
    export_json(results, summary, json_path, hints=[Hint("all_refused")])
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["tool"] == "sinko-probe"
    assert payload["summary"]["target_name"] == XSS_NAME
    assert payload["results"][0]["passed_expectation"] is True
    assert payload["hints"] == [{"key": "all_refused", "params": {}}]

    csv_path = tmp_path / "audit.csv"
    export_csv(results, csv_path)
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows[1]["cname_chain"] == f"{XSS_CNAME};{MARKUP}"
    assert rows[0]["passed_expectation"] == "True"

    empty = tmp_path / "empty.csv"
    export_csv([], empty)
    assert empty.read_text(encoding="utf-8").startswith("target_name,")


# -- Telegram ----------------------------------------------------------------------------------

TOKEN = "123456:SECRET-TOKEN"


def test_telegram_message_is_escaped_html(summary):
    message = build_telegram_message(summary)
    assert "&lt;script&gt;" in message
    assert "<script>" not in message
    assert "Homework &amp; &lt;Mode&gt;" in message
    assert message.startswith("⚠️")


def test_telegram_send_success(summary):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        send_telegram_summary(TOKEN, "42", summary, client=client)
    assert seen["url"].endswith(f"/bot{TOKEN}/sendMessage")
    assert seen["body"]["parse_mode"] == "HTML"
    assert seen["body"]["chat_id"] == "42"


def test_telegram_errors_never_leak_the_token(summary):
    def rejected(request):
        return httpx.Response(400, json={"ok": False, "description": "Bad Request: chat not found"})

    with (
        httpx.Client(transport=httpx.MockTransport(rejected)) as client,
        pytest.raises(NotificationError) as info,
    ):
        send_telegram_summary(TOKEN, "42", summary, client=client)
    assert "chat not found" in str(info.value)
    assert TOKEN not in str(info.value)

    def offline(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(offline)) as client,
        pytest.raises(NotificationError) as info,
    ):
        send_telegram_summary(TOKEN, "42", summary, client=client)
    assert "<redacted>" in str(info.value)
    assert "SECRET" not in str(info.value)
