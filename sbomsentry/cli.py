"""
Unified Command-Line Interface for SBOMsentry.
"""

import argparse
import json
import sys

from sbomsentry.analyzers.license_auditor import LicenseAuditor
from sbomsentry.analyzers.remediation_synthesizer import RemediationSynthesizer
from sbomsentry.analyzers.typosquat_detector import TyposquatDetector
from sbomsentry.analyzers.vulnerability_engine import VulnerabilityEngine
from sbomsentry.core.graph_engine import DependencyGraphEngine
from sbomsentry.core.models import Ecosystem, SupplyChainReport
from sbomsentry.core.sbom_parser import SBOMParser
from sbomsentry.reporters.cli_reporter import CLIReporter
from sbomsentry.reporters.html_reporter import HTMLReporter


def compute_risk_score(vulnerabilities, typosquats, license_issues) -> int:
    score = 0
    # Vuln scoring
    for v in vulnerabilities:
        if v.severity == "CRITICAL":
            score += 25
        elif v.severity == "HIGH":
            score += 15
        elif v.severity == "MEDIUM":
            score += 8
        else:
            score += 3

    # Typosquat scoring
    for t in typosquats:
        score += 20 if t.severity == "CRITICAL" else 15

    # License scoring
    for l in license_issues:
        if l.risk_level == "CRITICAL":
            score += 20
        elif l.risk_level == "HIGH":
            score += 10

    return min(100, score)


def run_audit(input_file: str, proprietary_mode: bool = True) -> tuple[SupplyChainReport, DependencyGraphEngine]:
    target_name, components, raw_edges = SBOMParser.parse_file(input_file)
    graph_engine = DependencyGraphEngine(target_name, components, raw_edges)
    direct_cnt, trans_cnt = graph_engine.get_statistics()

    # Detect ecosystem from first component or default
    eco = components[0].ecosystem if components else Ecosystem.GENERIC

    # Run analyzers
    vuln_engine = VulnerabilityEngine()
    vulnerabilities = vuln_engine.scan_components(components, graph_engine)

    typosquat_engine = TyposquatDetector()
    typosquats = typosquat_engine.analyze(components)

    license_engine = LicenseAuditor(proprietary_mode=proprietary_mode)
    license_issues = license_engine.audit_components(components)

    remediations = RemediationSynthesizer.synthesize(vulnerabilities, eco)

    risk_score = compute_risk_score(vulnerabilities, typosquats, license_issues)

    report = SupplyChainReport(
        target_name=target_name,
        components_count=len(components),
        direct_count=direct_cnt,
        transitive_count=trans_cnt,
        vulnerabilities=vulnerabilities,
        typosquats=typosquats,
        license_issues=license_issues,
        remediations=remediations,
        risk_score=risk_score,
    )
    return report, graph_engine


def handle_scan(args: argparse.Namespace) -> int:
    try:
        report, _ = run_audit(args.input, proprietary_mode=not args.allow_copyleft)
    except Exception as e:
        print(f"[ERROR] Audit failed on {args.input}: {e}")
        return 1

    # 1. Print terminal summary
    CLIReporter.print_summary(report)

    # 2. JSON Export
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"📄 JSON report saved to {args.output_json}")

    # 3. HTML Export
    if args.output_html:
        html = HTMLReporter.generate(report)
        with open(args.output_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📊 Interactive HTML report saved to {args.output_html}")

    # 4. CI Gate evaluation
    if args.fail_on_cvss > 0:
        high_cvss = any(v.cvss_score >= args.fail_on_cvss for v in report.vulnerabilities)
        if high_cvss:
            print(f"❌ CI Gate Failed: Found vulnerability with CVSS >= {args.fail_on_cvss}")
            return 2

    if args.fail_on_typosquat and report.typosquats:
        print("❌ CI Gate Failed: Suspected typosquatting dependency detected!")
        return 3

    return 0


def handle_graph(args: argparse.Namespace) -> int:
    try:
        target_name, components, raw_edges = SBOMParser.parse_file(args.input)
        graph = DependencyGraphEngine(target_name, components, raw_edges)
    except Exception as e:
        print(f"[ERROR] Failed to construct graph: {e}")
        return 1

    path = graph.get_shortest_path_from_root(args.target_component)
    print(f"\n📦 Dependency Reachability Path for '{args.target_component}':")
    print("   " + " -> ".join(path) + "\n")
    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    try:
        report, _ = run_audit(args.input)
    except Exception as e:
        print(f"[ERROR] Remediation analysis failed: {e}")
        return 1

    if not report.remediations:
        print(f"✅ No vulnerable components requiring remediation in {args.input}!")
        return 0

    print(f"\n🔧 [SBOMsentry] Recommended Remediation Plan for {report.target_name}:")
    print("=" * 70)
    for idx, r in enumerate(report.remediations, 1):
        print(f"[{idx:02d}] {r.component_name} ({r.current_version} -> {r.recommended_version})")
        print(f"     Risk:    {r.breaking_change_risk}")
        print(f"     Resolves: {', '.join(r.resolved_vulnerabilities)}")
        print(f"     Execute: {r.command_suggestion}\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="sbomsentry",
        description="SBOMsentry: Autonomous Software Supply Chain Security & SBOM Intelligence Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Comprehensive supply chain audit of SBOM or manifest")
    p_scan.add_argument("--input", "-i", required=True, help="Path to CycloneDX, SPDX, or lockfile")
    p_scan.add_argument("--output-json", default="", help="Path to write JSON report")
    p_scan.add_argument("--output-html", default="", help="Path to write interactive HTML dashboard")
    p_scan.add_argument("--fail-on-cvss", type=float, default=0.0, help="Fail CI if CVSS >= threshold (e.g. 7.0)")
    p_scan.add_argument("--fail-on-typosquat", action="store_true", help="Fail CI if any typosquat is detected")
    p_scan.add_argument("--allow-copyleft", action="store_true", help="Do not flag GPL/AGPL copyleft licenses")

    # graph
    p_graph = subparsers.add_parser("graph", help="Trace dependency reachability path from root to component")
    p_graph.add_argument("--input", "-i", required=True, help="Path to CycloneDX, SPDX, or lockfile")
    p_graph.add_argument("--target-component", "-t", required=True, help="Target component name to trace")

    # remediate
    p_remedy = subparsers.add_parser("remediate", help="Generate automated patch & upgrade plan")
    p_remedy.add_argument("--input", "-i", required=True, help="Path to CycloneDX, SPDX, or lockfile")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "graph":
        return handle_graph(args)
    elif args.command == "remediate":
        return handle_remediate(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
