"""
License Compliance and Copyleft Auditor for SBOMsentry.
"""

from sbomsentry.core.models import Component, LicenseCategory, LicenseFinding

# License Classification Mapping
LICENSE_MAP = {
    # Permissive
    "mit": LicenseCategory.PERMISSIVE,
    "apache-2.0": LicenseCategory.PERMISSIVE,
    "bsd-2-clause": LicenseCategory.PERMISSIVE,
    "bsd-3-clause": LicenseCategory.PERMISSIVE,
    "isc": LicenseCategory.PERMISSIVE,
    "unlicense": LicenseCategory.PERMISSIVE,
    "cc0-1.0": LicenseCategory.PERMISSIVE,
    # Weak Copyleft
    "lgpl-2.1": LicenseCategory.WEAK_COPYLEFT,
    "lgpl-3.0": LicenseCategory.WEAK_COPYLEFT,
    "mpl-2.0": LicenseCategory.WEAK_COPYLEFT,
    "epl-2.0": LicenseCategory.WEAK_COPYLEFT,
    # Strong Copyleft
    "gpl-2.0": LicenseCategory.STRONG_COPYLEFT,
    "gpl-3.0": LicenseCategory.STRONG_COPYLEFT,
    "gpl-2.0-only": LicenseCategory.STRONG_COPYLEFT,
    "gpl-3.0-only": LicenseCategory.STRONG_COPYLEFT,
    # Network Copyleft
    "agpl-3.0": LicenseCategory.NETWORK_COPYLEFT,
    "agpl-3.0-only": LicenseCategory.NETWORK_COPYLEFT,
    "sspl-1.0": LicenseCategory.NETWORK_COPYLEFT,
}


class LicenseAuditor:
    """Evaluates component licenses for legal compliance, commercial risks, and copyleft infection."""

    def __init__(self, proprietary_mode: bool = True):
        self.proprietary_mode = proprietary_mode

    def audit_components(self, components: list[Component]) -> list[LicenseFinding]:
        findings: list[LicenseFinding] = []

        for comp in components:
            if not comp.licenses:
                findings.append(
                    LicenseFinding(
                        component_name=comp.name,
                        declared_license="None / Unspecified",
                        category=LicenseCategory.UNKNOWN,
                        risk_level="MEDIUM",
                        description=f"Component '{comp.name}' does not declare a recognized open-source license. Legal liability unknown.",
                    )
                )
                continue

            for lic in comp.licenses:
                clean_lic = lic.lower().strip()
                cat = LICENSE_MAP.get(clean_lic, LicenseCategory.UNKNOWN)

                if cat == LicenseCategory.NETWORK_COPYLEFT and self.proprietary_mode:
                    findings.append(
                        LicenseFinding(
                            component_name=comp.name,
                            declared_license=lic,
                            category=cat,
                            risk_level="CRITICAL",
                            description=f"Network Copyleft ({lic}) detected! Distributing or hosting this component over a network may mandate disclosing proprietary source code under AGPL/SSPL.",
                        )
                    )
                elif cat == LicenseCategory.STRONG_COPYLEFT and self.proprietary_mode:
                    findings.append(
                        LicenseFinding(
                            component_name=comp.name,
                            declared_license=lic,
                            category=cat,
                            risk_level="HIGH",
                            description=f"Strong Copyleft ({lic}) detected. Linking or distributing with proprietary software may impose reciprocal GPL source code disclosure requirements.",
                        )
                    )
                elif cat == LicenseCategory.WEAK_COPYLEFT and self.proprietary_mode:
                    findings.append(
                        LicenseFinding(
                            component_name=comp.name,
                            declared_license=lic,
                            category=cat,
                            risk_level="LOW",
                            description=f"Weak Copyleft ({lic}) detected. Ensure any direct modifications to this library are provided upon request.",
                        )
                    )
                elif cat == LicenseCategory.UNKNOWN:
                    findings.append(
                        LicenseFinding(
                            component_name=comp.name,
                            declared_license=lic,
                            category=cat,
                            risk_level="MEDIUM",
                            description=f"Unrecognized or custom license '{lic}'. Manual legal review advised.",
                        )
                    )

        return findings
