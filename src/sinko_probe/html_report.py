"""Standalone HTML dashboard.

The page is one self-contained file: no external fonts, scripts or images, so it works offline
and can be attached to an e-mail. Every value is HTML-escaped (target names come from the command
line and CNAMEs from whatever the resolver answered), and a Content-Security-Policy only lets the
page's own inline script run. Filters work without JavaScript through CSS ``:has()``; the script
adds search, sorting and a theme toggle on top.
"""

import base64
import hashlib
import html
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

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

REPO_URL = "https://github.com/iret33/sinko-probe"
GAUGE_RADIUS = 52
GAUGE_CIRCUMFERENCE = 2 * 3.141592653589793 * GAUGE_RADIUS
FILTERS = (
    ("all", "filter_all"),
    ("fail", "filter_failures"),
    ("error", "filter_errors"),
    ("inconclusive", "filter_inconclusive"),
    ("pass", "filter_passed"),
)

STYLE = """
:root {
  color-scheme: light;
  --bg: #f4f7fb; --surface: #ffffff; --surface-2: #eef2f7; --border: #dde4ee;
  --text: #0f172a; --muted: #475569; --brand: #0f766e; --brand-soft: #ccfbf1;
  --good: #15803d; --good-bg: #dcfce7; --warn: #a16207; --warn-bg: #fef3c7;
  --bad: #b91c1c; --bad-bg: #fee2e2; --info: #1d4ed8; --info-bg: #dbeafe;
  --neutral: #334155; --neutral-bg: #e2e8f0; --track: #e2e8f0;
  --shadow: 0 1px 2px rgb(15 23 42 / 6%), 0 4px 16px rgb(15 23 42 / 6%);
  --radius: 14px;
  --font: system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", "Noto Sans Arabic",
    "Geeza Pro", Tahoma, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --bg: #0b1120; --surface: #111a2e; --surface-2: #17223a; --border: #24324f;
    --text: #e2e8f0; --muted: #9fb0c8; --brand: #2dd4bf; --brand-soft: rgb(45 212 191 / 14%);
    --good: #4ade80; --good-bg: rgb(74 222 128 / 14%); --warn: #fbbf24;
    --warn-bg: rgb(251 191 36 / 14%); --bad: #f87171; --bad-bg: rgb(248 113 113 / 15%);
    --info: #7cb2ff; --info-bg: rgb(96 165 250 / 15%); --neutral: #cbd5e1;
    --neutral-bg: rgb(148 163 184 / 16%); --track: #24324f;
    --shadow: 0 1px 2px rgb(0 0 0 / 30%), 0 8px 24px rgb(0 0 0 / 25%);
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0b1120; --surface: #111a2e; --surface-2: #17223a; --border: #24324f;
  --text: #e2e8f0; --muted: #9fb0c8; --brand: #2dd4bf; --brand-soft: rgb(45 212 191 / 14%);
  --good: #4ade80; --good-bg: rgb(74 222 128 / 14%); --warn: #fbbf24;
  --warn-bg: rgb(251 191 36 / 14%); --bad: #f87171; --bad-bg: rgb(248 113 113 / 15%);
  --info: #7cb2ff; --info-bg: rgb(96 165 250 / 15%); --neutral: #cbd5e1;
  --neutral-bg: rgb(148 163 184 / 16%); --track: #24324f;
  --shadow: 0 1px 2px rgb(0 0 0 / 30%), 0 8px 24px rgb(0 0 0 / 25%);
}
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 var(--font);
  overflow-wrap: break-word;
}
.page { max-width: 1240px; margin: 0 auto; padding: 24px 16px 48px; }
@media (min-width: 720px) { .page { padding: 32px 28px 64px; } }
a { color: var(--brand); }
code, .mono { font-family: var(--mono); font-size: 0.86em; }
.sr-only {
  position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden;
  clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.skip { position: absolute; inset-inline-start: 16px; top: -48px; z-index: 2; padding: 8px 12px;
  background: var(--surface); border-radius: 8px; }
.skip:focus { top: 12px; }
:focus-visible { outline: 3px solid var(--brand); outline-offset: 2px; }

.masthead { display: grid; gap: 18px; margin-bottom: 24px; }
.brand { display: flex; align-items: center; gap: 14px; }
.brand svg { flex: none; width: 46px; height: 46px; }
.eyebrow { margin: 0; color: var(--muted); font-size: 0.8rem; letter-spacing: 0.06em;
  text-transform: uppercase; }
h1 { margin: 2px 0 0; font-size: clamp(1.35rem, 1rem + 1.6vw, 1.9rem); line-height: 1.2; }
.title-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.theme { flex: none; display: grid; place-items: center; width: 40px; height: 40px;
  border-radius: 999px; border: 1px solid var(--border); background: var(--surface);
  color: var(--text); cursor: pointer; }
.theme[hidden] { display: none; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px;
  margin: 0; }
.meta div { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 8px 12px; min-width: 0; }
.meta dt { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; }
.meta dd { margin: 2px 0 0; font-weight: 600; }

.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 18px; margin-bottom: 20px; }
@media (min-width: 720px) { .card { padding: 22px 24px; } }
.card > h2, .findings h2 { margin: 0 0 14px; font-size: 1.1rem; }

.overview { display: grid; gap: 20px; align-items: center; }
@media (min-width: 900px) { .overview { grid-template-columns: 220px 1fr; } }
.gauge { position: relative; width: 190px; height: 190px; margin: 0 auto; }
.gauge svg { width: 100%; height: 100%; transform: rotate(-90deg); }
.gauge circle { fill: none; stroke-width: 12; }
.gauge .track { stroke: var(--track); }
.gauge .bar { stroke: currentColor; stroke-linecap: round; }
.gauge-label { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
.gauge-label strong { font-size: 2.1rem; line-height: 1; font-variant-numeric: tabular-nums; }
.gauge-label span { color: var(--muted); font-size: 0.82rem; margin-top: 6px; }
.counts { margin: 8px 0 0; text-align: center; color: var(--muted); font-size: 0.85rem; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }
@media (min-width: 900px) { .kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); } }
.kpi { border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
  background: var(--surface-2); border-inline-start: 4px solid var(--neutral); }
.kpi h3 { margin: 0; color: var(--muted); font-size: 0.78rem; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.04em; }
.kpi .value { margin: 4px 0 2px; font-size: 1.6rem; font-weight: 700; font-variant-numeric: tabular-nums; }
.kpi .help { margin: 0; color: var(--muted); font-size: 0.8rem; }
.kpi.compact .value { font-size: 1.25rem; padding-block: 0.2rem; }
.tone-good { color: var(--good); } .tone-warn { color: var(--warn); }
.tone-bad { color: var(--bad); } .tone-neutral { color: var(--neutral); }
.kpi.tone-good { border-inline-start-color: var(--good); }
.kpi.tone-warn { border-inline-start-color: var(--warn); }
.kpi.tone-bad { border-inline-start-color: var(--bad); }
.kpi h3, .kpi .help { color: var(--muted); }
.kpi.tone-good .value { color: var(--good); } .kpi.tone-warn .value { color: var(--warn); }
.kpi.tone-bad .value { color: var(--bad); } .kpi.tone-neutral .value { color: var(--text); }

.findings { border-color: var(--warn); background: var(--warn-bg); box-shadow: none; }
.findings ul { margin: 0; padding-inline-start: 20px; }
.findings li + li { margin-top: 6px; }

.table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th, td { padding: 10px 12px; text-align: start; vertical-align: top; border-bottom: 1px solid var(--border); }
thead th { position: sticky; top: 0; background: var(--surface-2); color: var(--muted);
  font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: var(--surface-2); }
.num { text-align: end; font-variant-numeric: tabular-nums; white-space: nowrap; }
.sub { display: block; width: fit-content; text-align: match-parent; color: var(--muted);
  font-size: 0.8rem; }
.nowrap { white-space: nowrap; }
.sort { all: unset; cursor: pointer; }
.sort:focus-visible { outline: 3px solid var(--brand); outline-offset: 2px; border-radius: 4px; }
.sort::after { content: " ↕"; opacity: 0.45; }
th[aria-sort="ascending"] .sort::after { content: " ↑"; opacity: 1; }
th[aria-sort="descending"] .sort::after { content: " ↓"; opacity: 1; }
.meter { display: inline-block; width: 64px; height: 6px; border-radius: 99px;
  background: var(--track); vertical-align: middle; margin-inline-end: 8px; overflow: hidden; }
.meter i { display: block; height: 100%; background: currentColor; border-radius: inherit; }

.pill, .badge, .tag { display: inline-block; border-radius: 999px; padding: 2px 9px;
  font-size: 0.75rem; font-weight: 650; white-space: nowrap; }
.tag { background: var(--neutral-bg); color: var(--neutral); font-weight: 500; }
.v-blocked { background: var(--brand-soft); color: var(--brand); }
.v-safesearch { background: var(--info-bg); color: var(--info); }
.v-allowed { background: var(--neutral-bg); color: var(--neutral); }
.v-inconclusive { background: var(--warn-bg); color: var(--warn); }
.v-error { background: var(--bad-bg); color: var(--bad); }
.b-pass { background: var(--good-bg); color: var(--good); }
.b-fail { background: var(--bad-bg); color: var(--bad); }
.b-error { background: var(--bad-bg); color: var(--bad); outline: 1px dashed var(--bad); }
.b-inconclusive { background: var(--warn-bg); color: var(--warn); }
.answer code { color: var(--muted); }

.toolbar { display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: center; margin-bottom: 14px; }
.filters { display: flex; flex-wrap: wrap; gap: 6px; margin: 0; padding: 0; border: 0; }
.filters input { position: absolute; opacity: 0; pointer-events: none; }
.filters label { cursor: pointer; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--border);
  background: var(--surface-2); font-size: 0.85rem; }
.filters label .count { color: var(--muted); font-variant-numeric: tabular-nums; }
.filters input:checked + label { background: var(--brand); border-color: var(--brand); color: var(--surface); }
.filters input:checked + label .count { color: inherit; opacity: 0.85; }
.filters input:focus-visible + label { outline: 3px solid var(--brand); outline-offset: 2px; }
.search input { width: min(280px, 100%); padding: 8px 12px; border-radius: 10px;
  border: 1px solid var(--border); background: var(--surface); color: var(--text); font: inherit; }
.search { flex: 1 1 200px; }
.shown { margin: 0; color: var(--muted); font-size: 0.85rem; }

#details:has(#f-fail:checked) tbody tr:not([data-outcome="fail"]),
#details:has(#f-error:checked) tbody tr:not([data-outcome="error"]),
#details:has(#f-inconclusive:checked) tbody tr:not([data-outcome="inconclusive"]),
#details:has(#f-pass:checked) tbody tr:not([data-outcome="pass"]) { display: none; }

@media (max-width: 719px) {
  table.probes thead { display: none; }
  table.probes, table.probes tbody, table.probes tr, table.probes td { display: block; width: 100%; }
  table.probes tr { padding: 10px 12px; border-bottom: 1px solid var(--border); }
  table.probes td { border: 0; padding: 3px 0; display: grid; grid-template-columns: 7.5em 1fr; gap: 8px; }
  table.probes td::before { content: attr(data-label); color: var(--muted); font-size: 0.75rem;
    text-transform: uppercase; letter-spacing: 0.03em; padding-top: 2px; }
  table.probes td.num { text-align: start; }
}
tr[hidden] { display: none !important; }
footer { color: var(--muted); font-size: 0.82rem; text-align: center; margin-top: 28px; }
@media print {
  :root { color-scheme: light; }
  body { background: #fff; color: #000; }
  .toolbar, .theme, .skip { display: none !important; }
  .card { box-shadow: none; break-inside: avoid; }
  table.probes tbody tr { display: table-row !important; }
}
"""

SCRIPT = """
(() => {
  const root = document.documentElement;
  const KEY = "sinko-probe-theme";
  try {
    const saved = localStorage.getItem(KEY);
    if (saved === "light" || saved === "dark") root.dataset.theme = saved;
  } catch (_) {}
  const toggle = document.getElementById("theme");
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener("click", () => {
      const dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try { localStorage.setItem(KEY, root.dataset.theme); } catch (_) {}
    });
  }

  const table = document.querySelector("table.probes");
  if (!table) return;
  const body = table.tBodies[0];
  const rows = Array.from(body.rows);
  const search = document.getElementById("q");
  const shown = document.getElementById("shown");
  const filters = Array.from(document.querySelectorAll('input[name="outcome"]'));

  const update = () => {
    const query = search ? search.value.trim().toLowerCase() : "";
    const active = filters.find((input) => input.checked);
    const outcome = active ? active.value : "all";
    let visible = 0;
    for (const row of rows) {
      const show = (outcome === "all" || row.dataset.outcome === outcome)
        && (query === "" || row.dataset.search.includes(query));
      row.hidden = !show;
      if (show) visible += 1;
    }
    if (shown) {
      shown.textContent = shown.dataset.template
        .replace("{shown}", String(visible))
        .replace("{total}", String(rows.length));
      shown.hidden = false;
    }
  };

  if (search) {
    search.closest("label").hidden = false;
    search.addEventListener("input", update);
  }
  filters.forEach((input) => input.addEventListener("change", update));

  table.querySelectorAll("th[data-sort]").forEach((th) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sort";
    button.textContent = th.textContent;
    th.textContent = "";
    th.appendChild(button);
    button.addEventListener("click", () => {
      const ascending = th.getAttribute("aria-sort") !== "ascending";
      table.querySelectorAll("th[aria-sort]").forEach((other) => other.removeAttribute("aria-sort"));
      th.setAttribute("aria-sort", ascending ? "ascending" : "descending");
      const index = th.cellIndex;
      const numeric = th.dataset.sort === "number";
      const key = (row) => {
        const cell = row.cells[index];
        const raw = cell.dataset.value !== undefined ? cell.dataset.value : cell.textContent;
        if (!numeric) return raw.trim().toLowerCase();
        const number = parseFloat(raw);
        return Number.isNaN(number) ? null : number;
      };
      const direction = ascending ? 1 : -1;
      rows
        .slice()
        .sort((a, b) => {
          const x = key(a);
          const y = key(b);
          if (!numeric) return direction * x.localeCompare(y);
          if (x === null || y === null) return (x === null) - (y === null);
          return direction * (x - y);
        })
        .forEach((row) => body.appendChild(row));
    });
  });

  update();
})();
"""

SHIELD_SVG = (
    '<svg viewBox="0 0 48 48" aria-hidden="true">'
    '<path d="M24 3 6 10v12c0 11.1 7.7 21.5 18 24 10.3-2.5 18-12.9 18-24V10L24 3Z" '
    'fill="var(--brand)"/>'
    '<path d="m16.5 24.5 5 5 10-11" fill="none" stroke="var(--surface)" stroke-width="4" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
THEME_ICON = (
    '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">'
    '<circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="2"/>'
    '<path d="M12 3.5a8.5 8.5 0 0 1 0 17z" fill="currentColor"/></svg>'
)
FAVICON = (
    "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E"
    "%3Cpath d='M24 3 6 10v12c0 11.1 7.7 21.5 18 24 10.3-2.5 18-12.9 18-24V10L24 3Z' "
    "fill='%230f766e'/%3E%3C/svg%3E"
)


def _csp_hash(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode("ascii")


CSP = (
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
    f"script-src '{_csp_hash(SCRIPT)}'; base-uri 'none'; form-action 'none'"
)


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def breakable(value: str) -> str:
    """Escape a domain-like value and let it wrap only between labels, never mid-label."""
    return esc(value).replace(".", ".<wbr>").replace("://", "://<wbr>")


def ltr(value_html: str) -> str:
    """Isolate a left-to-right value (``12.5 ms``) so RTL pages do not render ``ms 12.5``."""
    return f'<bdi dir="ltr">{value_html}</bdi>'


def _tone_for_score(value: float | None) -> str:
    if value is None:
        return "neutral"
    return "good" if value >= 85 else ("warn" if value >= 60 else "bad")


def _tone_for_problems(value: float | None, warn_below: float = 5.0) -> str:
    if value is None:
        return "neutral"
    if value == 0:
        return "good"
    return "warn" if value < warn_below else "bad"


def _verdict_class(verdict: Verdict) -> str:
    if verdict.is_blocked:
        return "v-blocked"
    if verdict.is_error:
        return "v-error"
    if verdict == Verdict.SAFESEARCH_ENFORCED:
        return "v-safesearch"
    if verdict == Verdict.UPSTREAM_NXDOMAIN:
        return "v-inconclusive"
    return "v-allowed"


def _app_cell(result: ProbeResult, lang: Lang) -> str:
    if lang == Lang.AR:
        primary, secondary, other = result.app_name_ar, result.app_name, ("en", "ltr")
    else:
        primary, secondary, other = result.app_name, result.app_name_ar, ("ar", "rtl")
    sub = (
        f'<span class="sub" lang="{other[0]}" dir="{other[1]}">{esc(secondary)}</span>'
        if secondary and secondary != primary
        else ""
    )
    return f"<strong>{esc(primary)}</strong>{sub}"


def _answer_cell(result: ProbeResult) -> str:
    if result.verdict.is_error:
        return f'<code dir="ltr">{esc(result.error_message or "—")}</code>'
    parts = []
    if result.cname_chain:
        parts.append("CNAME " + " → ".join(breakable(name) for name in result.cname_chain))
    if result.resolved_ips:
        extra = len(result.resolved_ips) - 4
        parts.append(esc(", ".join(result.resolved_ips[:4]) + (f" +{extra}" if extra > 0 else "")))
    if result.ede_codes:
        parts.append("EDE " + esc(", ".join(map(str, result.ede_codes))))
    if result.verdict == Verdict.UPSTREAM_NXDOMAIN and result.error_message:
        parts.append(esc(result.error_message))
    return "<br>".join(f'<code dir="ltr">{part}</code>' for part in parts) or "—"


def _probe_row(group: ProbeGroup, lang: Lang) -> str:
    first = group.first
    latest = group.latest_answer
    domain = first.domain if first.qname in (None, first.domain) else f"*.{first.domain}"
    verdict = group.verdict
    outcome = group.outcome
    badge = esc(outcome_label(outcome, lang))
    if group.runs > 1:
        badge += f" {group.passes}/{group.runs}"
    latency = group.median_latency_ms
    search_text = " ".join(
        [
            first.app_name,
            first.app_name_ar,
            domain,
            category_label(first.category, lang),
            verdict_label(verdict, lang),
            " ".join(latest.cname_chain),
            " ".join(latest.resolved_ips),
        ]
    ).lower()
    cells = [
        (t("col_app", lang), _app_cell(first, lang), ""),
        (t("col_domain", lang), f'<code dir="ltr">{breakable(domain)}</code>', ""),
        (
            t("col_category", lang),
            f'<span class="tag">{esc(category_label(first.category, lang))}</span>',
            "",
        ),
        (t("col_expected", lang), esc(expected_label(first.expected, lang)), ' class="nowrap"'),
        (
            t("col_verdict", lang),
            f'<span class="pill {_verdict_class(verdict)}">{esc(verdict_label(verdict, lang))}</span>',
            "",
        ),
        (t("col_answer", lang), _answer_cell(latest), ' class="answer"'),
        (
            t("col_latency", lang),
            ltr(esc(format_ms(latency, lang))),
            f' class="num" data-value="{"" if latency is None else latency}"',
        ),
        (
            t("col_result", lang),
            f'<span class="badge b-{outcome.value}">{badge}</span>',
            f' data-value="{outcome.value}"',
        ),
    ]
    tds = "".join(
        f'<td data-label="{esc(label)}"{attrs}><div>{content}</div></td>'
        for label, content, attrs in cells
    )
    return f'<tr data-outcome="{outcome.value}" data-search="{esc(search_text)}">{tds}</tr>'


def _scorecard_rows(results: Sequence[ProbeResult], lang: Lang) -> str:
    rows = []
    for items in results_by_app(results).values():
        blocked = tally(items, ExpectedAction.BLOCK)
        safesearch = tally(items, ExpectedAction.SAFESEARCH)
        allowed = tally(items, ExpectedAction.ALLOW)
        passed = sum(i.outcome == Outcome.PASS for i in items)
        score = percent(passed, sum(i.outcome != Outcome.INCONCLUSIVE for i in items))
        latencies = answered_latencies(items)
        avg = sum(latencies) / len(latencies) if latencies else None
        errors = sum(i.outcome == Outcome.ERROR for i in items)
        tone = _tone_for_score(score)
        width = 0 if score is None else score
        rows.append(
            "<tr>"
            f"<td>{_app_cell(items[0], lang)}</td>"
            f'<td class="num">{len(items)}</td>'
            f'<td class="num">{blocked.passed}/{blocked.conclusive}</td>'
            f'<td class="num">{safesearch.passed}/{safesearch.conclusive}</td>'
            f'<td class="num">{allowed.passed}/{allowed.conclusive}</td>'
            f'<td class="num">{errors}</td>'
            f'<td class="num">{ltr(esc(format_ms(avg, lang)))}</td>'
            f'<td class="num tone-{tone}"><span class="meter" aria-hidden="true">'
            f'<i style="width:{width:.0f}%"></i></span>{esc(format_rate(score, lang))}</td>'
            "</tr>"
        )
    return "".join(rows)


def _kpi(title: str, value_html: str, help_text: str, tone: str, extra: str = "") -> str:
    return (
        f'<article class="kpi tone-{tone}{extra}"><h3>{esc(title)}</h3>'
        f'<p class="value">{value_html}</p><p class="help">{esc(help_text)}</p></article>'
    )


def _latency_triplet(summary: TargetSummary, lang: Lang) -> str:
    values = (summary.p50_ms, summary.p95_ms, summary.p99_ms)
    if all(v is None for v in values):
        return esc(t("na", lang))
    return ltr(esc(" / ".join("–" if v is None else f"{v:.1f}" for v in values) + " ms"))


def _gauge(score: float | None, lang: Lang) -> str:
    tone = _tone_for_score(score)
    filled = 0.0 if score is None else GAUGE_CIRCUMFERENCE * max(0.0, min(score, 100.0)) / 100
    label = format_rate(score, lang)
    title = t("kpi_compliance", lang)
    return (
        f'<div class="gauge tone-{tone}" role="img" aria-label="{esc(title)}: {esc(label)}">'
        '<svg viewBox="0 0 120 120" aria-hidden="true">'
        f'<circle class="track" cx="60" cy="60" r="{GAUGE_RADIUS}"/>'
        f'<circle class="bar" cx="60" cy="60" r="{GAUGE_RADIUS}" '
        f'stroke-dasharray="{filled:.2f} {GAUGE_CIRCUMFERENCE:.2f}"/></svg>'
        f'<div class="gauge-label"><strong>{esc(label)}</strong><span>{esc(title)}</span></div>'
        "</div>"
    )


def render_html(
    results: Sequence[ProbeResult],
    summary: TargetSummary,
    lang: Lang | str = Lang.EN,
    hints: Sequence[Hint] = (),
    generated_at: datetime | None = None,
) -> str:
    lang = Lang(lang)
    direction = "rtl" if lang == Lang.AR else "ltr"
    generated = (generated_at or datetime.now(timezone.utc)).replace(microsecond=0)
    groups = group_results(results)
    counts = {key: sum(g.outcome.value == key for g in groups) for key, _ in FILTERS[1:]}
    counts["all"] = len(groups)

    meta = [
        (t("label_target", lang), esc(summary.target_name)),
        (t("col_endpoint", lang), ltr(breakable(summary.server_endpoint))),
        (t("col_protocol", lang), esc(summary.protocol.value.upper())),
        (t("label_policy", lang), esc(summary.policy_name or t("label_no_policy", lang))),
        (t("label_waves", lang), str(summary.iterations)),
        (
            t("label_generated", lang),
            (
                f'<time dir="ltr" datetime="{generated.isoformat()}">'
                f"{esc(generated.strftime('%Y-%m-%d %H:%M UTC'))}</time>"
            ),
        ),
    ]
    meta_html = "".join(f"<div><dt>{esc(k)}</dt><dd>{v}</dd></div>" for k, v in meta)

    inconclusive_rate = percent(summary.inconclusive_probes, summary.total_probes)
    kpis = "".join(
        [
            _kpi(
                t("kpi_block", lang),
                esc(format_rate(summary.block_rate, lang)),
                t("kpi_block_help", lang),
                _tone_for_score(summary.block_rate),
            ),
            _kpi(
                t("kpi_safesearch", lang),
                esc(format_rate(summary.safesearch_rate, lang)),
                t("kpi_safesearch_help", lang),
                _tone_for_score(summary.safesearch_rate),
            ),
            _kpi(
                t("kpi_false_positives", lang),
                esc(format_rate(summary.false_positive_rate, lang)),
                t("kpi_false_positives_help", lang),
                _tone_for_problems(summary.false_positive_rate, warn_below=0.01),
            ),
            _kpi(
                t("kpi_errors", lang),
                esc(format_rate(summary.error_rate, lang)),
                t("kpi_errors_help", lang),
                _tone_for_problems(summary.error_rate),
            ),
            _kpi(
                t("kpi_inconclusive", lang),
                esc(format_rate(inconclusive_rate, lang)),
                t("kpi_inconclusive_help", lang),
                "neutral" if not summary.inconclusive_probes else "warn",
            ),
            _kpi(
                t("kpi_latency", lang),
                _latency_triplet(summary, lang),
                t("kpi_latency_help", lang),
                "neutral",
                " compact",
            ),
        ]
    )
    counts_line = t(
        "label_probes_summary",
        lang,
        passed=summary.passed_probes,
        failed=summary.failed_probes,
        errors=summary.error_probes,
        inconclusive=summary.inconclusive_probes,
    )

    findings = ""
    if hints:
        items = "".join(f"<li>{esc(t(f'hint_{h.key}', lang, **h.params))}</li>" for h in hints)
        findings = (
            f'<section class="card findings" aria-labelledby="findings-title">'
            f'<h2 id="findings-title">⚠️ {esc(t("label_findings", lang))}</h2><ul>{items}</ul></section>'
        )

    score_headers = "".join(
        f'<th scope="col"{" class=num" if i else ""}>{esc(t(key, lang))}</th>'
        for i, key in enumerate(
            (
                "col_app",
                "col_probes",
                "col_blocked",
                "col_safesearch",
                "col_allowed",
                "col_errors",
                "col_avg_latency",
                "col_score",
            )
        )
    )
    probe_headers = "".join(
        f'<th scope="col" data-sort="{kind}"{" class=num" if kind == "number" else ""}>'
        f"{esc(t(key, lang))}</th>"
        for key, kind in (
            ("col_app", "text"),
            ("col_domain", "text"),
            ("col_category", "text"),
            ("col_expected", "text"),
            ("col_verdict", "text"),
            ("col_answer", "text"),
            ("col_latency", "number"),
            ("col_result", "text"),
        )
    )
    filter_inputs = "".join(
        f'<input type="radio" name="outcome" id="f-{key}" value="{key}"'
        f"{' checked' if key == 'all' else ''}>"
        f'<label for="f-{key}">{esc(t(label, lang))} <span class="count">{counts[key]}</span></label>'
        for key, label in FILTERS
    )
    rows = "".join(_probe_row(group, lang) for group in groups)
    title = f"{t('report_title', lang)} — {summary.target_name}"

    return f"""<!DOCTYPE html>
<html lang="{lang.value}" dir="{direction}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="generator" content="sinko-probe {esc(__version__)}">
<title>{esc(title)}</title>
<link rel="icon" href="{FAVICON}">
<style>{STYLE}</style>
</head>
<body>
<a class="skip" href="#details">{esc(t("details_title", lang))}</a>
<div class="page">
<header class="masthead">
  <div class="title-row">
    <div class="brand">{SHIELD_SVG}<div><p class="eyebrow">Sinko-Probe {esc(__version__)}</p>
      <h1>{esc(t("report_title", lang))}</h1></div></div>
    <button id="theme" class="theme" type="button" aria-label="{esc(t("theme_toggle", lang))}"
      title="{esc(t("theme_toggle", lang))}" hidden>{THEME_ICON}</button>
  </div>
  <dl class="meta">{meta_html}</dl>
</header>
<main>
<section class="card overview" aria-label="{esc(t("summary_title", lang))}">
  <div>{_gauge(summary.compliance_score, lang)}<p class="counts">{esc(counts_line)}</p></div>
  <div class="kpis">{kpis}</div>
</section>
{findings}
<section class="card" aria-labelledby="scorecard-title">
  <h2 id="scorecard-title">{esc(t("scorecard_title", lang))}</h2>
  <div class="table-wrap"><table>
    <thead><tr>{score_headers}</tr></thead>
    <tbody>{_scorecard_rows(results, lang)}</tbody>
  </table></div>
</section>
<section class="card" id="details" aria-labelledby="details-title">
  <h2 id="details-title">{esc(t("details_title", lang))}</h2>
  <div class="toolbar">
    <fieldset class="filters"><legend class="sr-only">{esc(t("col_result", lang))}</legend>
      {filter_inputs}</fieldset>
    <label class="search" hidden><span class="sr-only">{esc(t("search_label", lang))}</span>
      <input type="search" id="q" placeholder="{esc(t("search_placeholder", lang))}"
        autocomplete="off"></label>
    <p id="shown" class="shown" aria-live="polite" hidden
      data-template="{esc(t("showing", lang))}"></p>
  </div>
  <div class="table-wrap"><table class="probes">
    <caption class="sr-only">{esc(t("details_title", lang))}</caption>
    <thead><tr>{probe_headers}</tr></thead>
    <tbody>{rows}</tbody>
  </table></div>
</section>
</main>
<footer>sinko-probe {esc(__version__)} · <a href="{REPO_URL}">{REPO_URL.removeprefix("https://")}</a></footer>
</div>
<script>{SCRIPT}</script>
</body>
</html>
"""


def export_html_dashboard(
    results: Sequence[ProbeResult],
    summary: TargetSummary,
    output_path: Path,
    lang: Lang | str = Lang.EN,
    hints: Sequence[Hint] = (),
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(results, summary, lang, hints), encoding="utf-8")
