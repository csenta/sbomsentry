"""
Automated Remediation Synthesizer for SBOMsentry.
Generates pinpoint version upgrades with minimal breaking change risk.
"""

from sbomsentry.core.models import Ecosystem, RemediationAction, VulnerabilityFinding


def parse_semver_parts(v_str: str) -> tuple[int, int, int]:
    import re
    cleaned = re.sub(r"^[vV]", "", v_str).split("-")[0].split("+")[0]
    parts = []
    for p in cleaned.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


class RemediationSynthesizer:
    """Synthesizes dependency upgrade plans to eliminate vulnerabilities with minimal friction."""

    @staticmethod
    def synthesize(
        vulnerabilities: list[VulnerabilityFinding],
        ecosystem: Ecosystem = Ecosystem.GENERIC,
    ) -> list[RemediationAction]:
        # Group vulnerabilities by component
        comp_vulns: dict[str, list[VulnerabilityFinding]] = {}
        for v in vulnerabilities:
            comp_vulns.setdefault(v.component_name, []).append(v)

        actions: list[RemediationAction] = []

        for comp_name, vulns in comp_vulns.items():
            current_v = vulns[0].component_version
            # Find the highest fixed_in version across all CVEs for this component
            highest_fix = vulns[0].fixed_in
            highest_fix_tuple = parse_semver_parts(highest_fix)

            for v in vulns[1:]:
                v_tuple = parse_semver_parts(v.fixed_in)
                if v_tuple > highest_fix_tuple:
                    highest_fix = v.fixed_in
                    highest_fix_tuple = v_tuple

            # Evaluate breaking change risk
            cur_major, cur_minor, cur_patch = parse_semver_parts(current_v)
            fix_major, fix_minor, fix_patch = highest_fix_tuple

            if fix_major > cur_major:
                breaking_risk = "HIGH (Major version bump)"
            elif fix_minor > cur_minor:
                breaking_risk = "MEDIUM (Minor version bump)"
            else:
                breaking_risk = "LOW (Patch update)"

            # Command suggestion
            vuln_ids = [v.id for v in vulns]
            if ecosystem == Ecosystem.NPM:
                cmd = f"npm install {comp_name}@{highest_fix}"
            elif ecosystem == Ecosystem.PYPI:
                cmd = f"pip install --upgrade {comp_name}=={highest_fix}"
            elif ecosystem == Ecosystem.GOLANG:
                cmd = f"go get {comp_name}@{highest_fix}"
            else:
                cmd = f"upgrade {comp_name} from {current_v} to {highest_fix}"

            actions.append(
                RemediationAction(
                    component_name=comp_name,
                    current_version=current_v,
                    recommended_version=highest_fix,
                    breaking_change_risk=breaking_risk,
                    resolved_vulnerabilities=vuln_ids,
                    command_suggestion=cmd,
                )
            )

        return actions
