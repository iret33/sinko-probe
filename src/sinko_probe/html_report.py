from datetime import datetime, timezone
from pathlib import Path
from typing import List
from .models import ProbeResult, TargetSummary


def export_html_dashboard(
    results: List[ProbeResult], summary: TargetSummary, output_path: Path
) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows_html = []
    for r in results:
        badge_cls = "pass" if r.passed_expectation else "fail"
        badge_txt = "PASS" if r.passed_expectation else "FAIL"
        target_detail = (
            f"CNAME: {', '.join(r.cname_chain)}"
            if r.cname_chain
            else (", ".join(r.resolved_ips) if r.resolved_ips else "—")
        )
        rows_html.append(
            f"""
            <tr>
                <td><strong>{r.app_name}</strong><br><small>{r.app_name_ar}</small></td>
                <td><code>{r.domain}</code></td>
                <td><span class="tag">{r.category.value}</span></td>
                <td>{r.expected.value.upper()}</td>
                <td>{r.verdict.value}</td>
                <td><code>{target_detail}</code></td>
                <td class="num">{r.latency_ms:.1f} ms</td>
                <td><span class="badge {badge_cls}">{badge_txt}</span></td>
            </tr>
            """
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sinko-Probe Audit Report — {summary.target_name}</title>
<style>
  :root {{ --bg: #0b1120; --card: #1e293b; --text: #f8fafc; --muted: #94a3b8; --teal: #14b8a6; --green: #22c55e; --red: #ef4444; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 32px; }}
  .container {{ max-width: 1240px; margin: 0 auto; }}
  header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ margin: 0; font-size: 1.6rem; color: var(--teal); }}
  .kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .kpi {{ background: var(--card); padding: 20px; border-radius: 12px; border: 1px solid #334155; }}
  .kpi .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }}
  .kpi .val {{ font-size: 1.9rem; font-weight: 700; margin-top: 6px; color: var(--teal); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 12px; overflow: hidden; }}
  th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.9rem; }}
  th {{ background: #0f172a; color: var(--muted); text-transform: uppercase; font-size: 0.78rem; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .badge {{ padding: 4px 10px; border-radius: 999px; font-weight: 700; font-size: 0.75rem; }}
  .pass {{ background: rgba(34,197,94,0.18); color: var(--green); }}
  .fail {{ background: rgba(239,68,68,0.18); color: var(--red); }}
  .tag {{ background: #334155; padding: 3px 8px; border-radius: 6px; font-size: 0.78rem; }}
  small {{ color: var(--muted); }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ Sinko-Probe Security & Parental Control Audit</h1>
      <small>Target: {summary.target_name} ({summary.server_endpoint} via {summary.protocol.value.upper()})</small>
    </div>
    <small>Generated: {timestamp}</small>
  </header>
  <section class="kpis">
    <div class="kpi"><div class="label">Compliance Score</div><div class="val">{summary.compliance_score:.1f}%</div></div>
    <div class="kpi"><div class="label">Block Efficacy</div><div class="val">{summary.block_rate:.1f}%</div></div>
    <div class="kpi"><div class="label">SafeSearch Enforced</div><div class="val">{summary.safesearch_rate:.1f}%</div></div>
    <div class="kpi"><div class="label">False Positives</div><div class="val">{summary.false_positive_rate:.1f}%</div></div>
    <div class="kpi"><div class="label">p50 / p95 Latency</div><div class="val">{summary.p50_ms} / {summary.p95_ms} ms</div></div>
  </section>
  <table>
    <thead>
      <tr>
        <th>Application</th><th>Domain</th><th>Category</th><th>Expected</th>
        <th>Verdict</th><th>Resolution / CNAME</th><th class="num">Latency</th><th>Audit</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>
</div>
</body>
</html>"""
    output_path.write_text(html, encoding="utf-8")
