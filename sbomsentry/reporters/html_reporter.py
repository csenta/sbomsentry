"""
Standalone Interactive HTML5 Dashboard Generator for SBOMsentry.
"""

import json
from sbomsentry.core.models import SupplyChainReport


class HTMLReporter:
    """Renders interactive self-contained HTML5 reports with dark theme."""

    @staticmethod
    def generate(report: SupplyChainReport, title: str = "SBOMsentry Supply Chain Audit") -> str:
        report_json = json.dumps(report.to_dict())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0b0f19;
      --card-bg: #151c2c;
      --card-border: #232f48;
      --text: #f1f5f9;
      --text-muted: #8e9db7;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
      --success: #10b981;
      --accent: #6366f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--card-border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #818cf8; display: flex; align-items: center; gap: 0.5rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 1.25rem; }}
    .stat-title {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.4rem; }}
    .risk-score {{ color: {("#ef4444" if report.risk_score >= 70 else ("#f59e0b" if report.risk_score >= 30 else "#10b981"))}; }}
    .section {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
    .section-title {{ font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ padding: 0.85rem; text-align: left; border-bottom: 1px solid var(--card-border); font-size: 0.9rem; }}
    th {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(245, 158, 11, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: var(--low); border: 1px solid var(--low); }}
    code {{ font-family: monospace; background: rgba(0,0,0,0.3); padding: 0.2rem 0.4rem; border-radius: 4px; }}
    .code-cmd {{ font-family: monospace; background: #070a12; border: 1px solid #1e293b; color: #38bdf8; padding: 0.4rem 0.8rem; border-radius: 4px; display: inline-block; margin-top: 0.25rem; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>🛡️ SBOMsentry Executive Audit</h1>
        <p style="color: var(--text-muted); margin-top: 0.25rem;">Software Supply Chain Security, Vulnerabilities & Typosquatting Intelligence</p>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-muted);">
        Target: <strong>{report.target_name}</strong> | {report.timestamp}
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Risk Index</div>
        <div class="stat-val risk-score">{report.risk_score} / 100</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Components</div>
        <div class="stat-val">{report.components_count}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Vulnerabilities</div>
        <div class="stat-val" style="color: {("#ef4444" if report.vulnerabilities else "#10b981")};">{len(report.vulnerabilities)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Typosquats</div>
        <div class="stat-val" style="color: {("#f97316" if report.typosquats else "#10b981")};">{len(report.typosquats)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">License Warnings</div>
        <div class="stat-val" style="color: {("#f59e0b" if report.license_issues else "#10b981")};">{len(report.license_issues)}</div>
      </div>
    </div>

    <!-- Vulnerabilities Table -->
    <div class="section">
      <div class="section-title">
        <span>🚨 Component Vulnerabilities ({len(report.vulnerabilities)})</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Advisory ID</th>
            <th>Component</th>
            <th>Reachability Path</th>
            <th>Summary & Fix</th>
          </tr>
        </thead>
        <tbody>
"""

        for v in report.vulnerabilities:
            sev_class = f"badge-{v.severity.lower()}"
            path_display = " -> ".join(v.reachable_path) if v.reachable_path else v.component_name
            html += f"""          <tr>
            <td><span class="badge {sev_class}">{v.severity}</span> (CVSS {v.cvss_score})</td>
            <td><strong>{v.id}</strong></td>
            <td><code>{v.component_name}@{v.component_version}</code></td>
            <td><code style="color: #a5b4fc;">{path_display}</code></td>
            <td>{v.summary} <br><strong style="color: var(--success); font-size: 0.8rem;">Fixed in {v.fixed_in}</strong></td>
          </tr>
"""

        if not report.vulnerabilities:
            html += "<tr><td colspan='5' style='text-align: center; color: var(--success);'>✅ No known vulnerabilities found.</td></tr>"

        html += f"""        </tbody>
      </table>
    </div>

    <!-- Typosquatting Table -->
    <div class="section">
      <div class="section-title">
        <span>⚠️ Typosquatting & Impersonation Suspects ({len(report.typosquats)})</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Component Name</th>
            <th>Target Canonical</th>
            <th>Similarity</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
"""
        for t in report.typosquats:
            html += f"""          <tr>
            <td><span class="badge badge-high">{t.severity}</span></td>
            <td><code>{t.component_name}</code></td>
            <td><strong style="color: #38bdf8;">{t.suspected_canonical}</strong></td>
            <td>{t.similarity:.0%}</td>
            <td>{t.reason}</td>
          </tr>
"""
        if not report.typosquats:
            html += "<tr><td colspan='5' style='text-align: center; color: var(--success);'>✅ No typosquats detected.</td></tr>"

        html += f"""        </tbody>
      </table>
    </div>

    <!-- Remediation Table -->
    <div class="section">
      <div class="section-title">
        <span>🔧 Automated Remediation Plan ({len(report.remediations)})</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Component</th>
            <th>Target Version</th>
            <th>Risk</th>
            <th>Resolves</th>
            <th>Suggested Command</th>
          </tr>
        </thead>
        <tbody>
"""
        for r in report.remediations:
            html += f"""          <tr>
            <td><strong>{r.component_name}</strong></td>
            <td><code>{r.current_version}</code> &rarr; <code style="color: var(--success);">{r.recommended_version}</code></td>
            <td>{r.breaking_change_risk}</td>
            <td>{", ".join(r.resolved_vulnerabilities)}</td>
            <td><div class="code-cmd">{r.command_suggestion}</div></td>
          </tr>
"""
        if not report.remediations:
            html += "<tr><td colspan='5' style='text-align: center; color: var(--success);'>✅ No remediations required.</td></tr>"

        html += f"""        </tbody>
      </table>
    </div>

  </div>
  <script>
    const reportData = {report_json};
    console.log("SBOMsentry Report Initialized:", reportData);
  </script>
</body>
</html>"""
        return html
