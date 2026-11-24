"""
Terminal Summary Reporter for SBOMsentry.
"""

from sbomsentry.core.models import SupplyChainReport


class CLIReporter:
    """Prints structured terminal reports for supply chain audits."""

    @staticmethod
    def print_summary(report: SupplyChainReport):
        print("\n" + "=" * 78)
        print("🛡️  [SBOMSENTRY] SOFTWARE SUPPLY CHAIN SECURITY AUDIT REPORT")
        print("=" * 78)
        print(f"  Target:                 {report.target_name}")
        print(f"  Total Components:       {report.components_count} (Direct: {report.direct_count}, Transitive: {report.transitive_count})")
        print(f"  Vulnerabilities Found:  {len(report.vulnerabilities)}")
        print(f"  Typosquat Suspects:     {len(report.typosquats)}")
        print(f"  License Violations:     {len(report.license_issues)}")

        score_emoji = "🟢" if report.risk_score < 30 else ("🟡" if report.risk_score < 70 else "🔴")
        print(f"  Supply Chain Risk Score: {score_emoji} {report.risk_score}/100")
        print("-" * 78)

        # 1. Vulnerabilities
        if report.vulnerabilities:
            print("\n🚨 VULNERABILITY FINDINGS (Reachability Traced):")
            for idx, v in enumerate(report.vulnerabilities, 1):
                badge = {
                    "CRITICAL": "💥 CRITICAL",
                    "HIGH": "🚨 HIGH    ",
                    "MEDIUM": "⚠️  MEDIUM  ",
                    "LOW": "ℹ️  LOW     ",
                }.get(v.severity, v.severity)
                path_str = " -> ".join(v.reachable_path) if v.reachable_path else v.component_name
                print(f"  [{idx:02d}] {badge} (CVSS {v.cvss_score:.1f}) | {v.id:<16} | {v.component_name}@{v.component_version} -> Fixed in {v.fixed_in}")
                print(f"       Summary:  {v.summary}")
                print(f"       Path:     {path_str}")

        # 2. Typosquats
        if report.typosquats:
            print("\n⚠️  SUPPLY CHAIN TYPOSQUATTING & IMPERSONATION RISKS:")
            for idx, t in enumerate(report.typosquats, 1):
                print(f"  [{idx:02d}] 🚨 {t.severity} | '{t.component_name}' impersonates canonical '{t.suspected_canonical}'")
                print(f"       Reason:     {t.reason}")
                print(f"       Similarity: {t.similarity:.0%}")

        # 3. License Issues
        if report.license_issues:
            print("\n⚖️  LICENSE COMPLIANCE & COPYLEFT RISKS:")
            for idx, l in enumerate(report.license_issues, 1):
                print(f"  [{idx:02d}] ⚠️  {l.risk_level:<8} | {l.component_name:<20} | Declared: {l.declared_license:<16} ({l.category.value})")
                print(f"       Notice: {l.description}")

        # 4. Remediation Plan
        if report.remediations:
            print("\n🔧 AUTOMATED REMEDIATION PLAN:")
            for idx, r in enumerate(report.remediations, 1):
                print(f"  [{idx:02d}] Upgrade {r.component_name} ({r.current_version} -> {r.recommended_version}) | Risk: {r.breaking_change_risk}")
                print(f"       Resolves: {', '.join(r.resolved_vulnerabilities)}")
                print(f"       Command:  {r.command_suggestion}")

        print("\n" + "=" * 78 + "\n")
