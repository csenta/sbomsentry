"""
Core Domain Models for SBOMsentry.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Ecosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    GOLANG = "golang"
    MAVEN = "maven"
    GENERIC = "generic"


class LicenseCategory(str, Enum):
    PERMISSIVE = "PERMISSIVE"
    WEAK_COPYLEFT = "WEAK_COPYLEFT"
    STRONG_COPYLEFT = "STRONG_COPYLEFT"
    NETWORK_COPYLEFT = "NETWORK_COPYLEFT"
    UNKNOWN = "UNKNOWN"


@dataclass
class Component:
    name: str
    version: str
    ecosystem: Ecosystem = Ecosystem.GENERIC
    purl: str = ""
    licenses: list[str] = field(default_factory=list)
    is_direct: bool = True
    dependencies: list[str] = field(default_factory=list)  # Target component names/keys
    hashes: dict[str, str] = field(default_factory=dict)
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class VulnerabilityFinding:
    id: str  # e.g., CVE-2023-32681 or GHSA-j8r2-6x86-q33q
    component_name: str
    component_version: str
    fixed_in: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    cvss_score: float
    summary: str
    advisory_url: str = ""
    reachable_path: list[str] = field(default_factory=list)  # e.g. ["root", "web-framework", "vulnerable-lib"]


@dataclass
class TyposquatFinding:
    component_name: str
    suspected_canonical: str
    distance: int
    similarity: float
    reason: str
    severity: str = "HIGH"


@dataclass
class LicenseFinding:
    component_name: str
    declared_license: str
    category: LicenseCategory
    risk_level: str  # HIGH, MEDIUM, LOW, INFO
    description: str


@dataclass
class RemediationAction:
    component_name: str
    current_version: str
    recommended_version: str
    breaking_change_risk: str  # LOW (patch), MEDIUM (minor), HIGH (major)
    resolved_vulnerabilities: list[str]
    command_suggestion: str


@dataclass
class SupplyChainReport:
    target_name: str
    components_count: int
    direct_count: int
    transitive_count: int
    vulnerabilities: list[VulnerabilityFinding] = field(default_factory=list)
    typosquats: list[TyposquatFinding] = field(default_factory=list)
    license_issues: list[LicenseFinding] = field(default_factory=list)
    remediations: list[RemediationAction] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "components_count": self.components_count,
            "direct_count": self.direct_count,
            "transitive_count": self.transitive_count,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
            "vulnerabilities": [
                {
                    "id": v.id,
                    "component": v.component_name,
                    "version": v.component_version,
                    "fixed_in": v.fixed_in,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "summary": v.summary,
                    "path": " -> ".join(v.reachable_path) if v.reachable_path else v.component_name,
                }
                for v in self.vulnerabilities
            ],
            "typosquats": [
                {
                    "component": t.component_name,
                    "suspected_canonical": t.suspected_canonical,
                    "similarity": round(t.similarity, 2),
                    "reason": t.reason,
                    "severity": t.severity,
                }
                for t in self.typosquats
            ],
            "license_issues": [
                {
                    "component": l.component_name,
                    "declared_license": l.declared_license,
                    "category": l.category.value,
                    "risk_level": l.risk_level,
                    "description": l.description,
                }
                for l in self.license_issues
            ],
            "remediations": [
                {
                    "component": r.component_name,
                    "current": r.current_version,
                    "recommended": r.recommended_version,
                    "breaking_risk": r.breaking_change_risk,
                    "resolves": r.resolved_vulnerabilities,
                    "command": r.command_suggestion,
                }
                for r in self.remediations
            ],
        }
