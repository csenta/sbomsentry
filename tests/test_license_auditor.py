import unittest
from sbomsentry.analyzers.license_auditor import LicenseAuditor
from sbomsentry.core.models import Component, LicenseCategory


class TestLicenseAuditor(unittest.TestCase):
    def test_copyleft_detection(self):
        components = [
            Component(name="lib-mit", version="1.0.0", licenses=["MIT"]),
            Component(name="lib-gpl", version="1.0.0", licenses=["GPL-3.0"]),
            Component(name="lib-agpl", version="1.0.0", licenses=["AGPL-3.0"]),
            Component(name="lib-unknown", version="1.0.0", licenses=[]),
        ]
        auditor = LicenseAuditor(proprietary_mode=True)
        findings = auditor.audit_components(components)

        agpl_finding = next(f for f in findings if f.component_name == "lib-agpl")
        self.assertEqual(agpl_finding.category, LicenseCategory.NETWORK_COPYLEFT)
        self.assertEqual(agpl_finding.risk_level, "CRITICAL")

        gpl_finding = next(f for f in findings if f.component_name == "lib-gpl")
        self.assertEqual(gpl_finding.category, LicenseCategory.STRONG_COPYLEFT)
        self.assertEqual(gpl_finding.risk_level, "HIGH")


if __name__ == "__main__":
    unittest.main()
