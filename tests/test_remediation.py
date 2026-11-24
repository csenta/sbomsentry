import unittest
from sbomsentry.analyzers.remediation_synthesizer import RemediationSynthesizer
from sbomsentry.core.models import Ecosystem, VulnerabilityFinding


class TestRemediation(unittest.TestCase):
    def test_synthesize_remediations(self):
        vulns = [
            VulnerabilityFinding(
                id="CVE-1",
                component_name="requests",
                component_version="2.28.1",
                fixed_in="2.31.0",
                severity="HIGH",
                cvss_score=7.5,
                summary="Leak",
            ),
            VulnerabilityFinding(
                id="CVE-2",
                component_name="requests",
                component_version="2.28.1",
                fixed_in="2.32.0",
                severity="CRITICAL",
                cvss_score=9.1,
                summary="Critical Leak",
            ),
        ]
        actions = RemediationSynthesizer.synthesize(vulns, Ecosystem.PYPI)
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action.component_name, "requests")
        self.assertEqual(action.recommended_version, "2.32.0")
        self.assertIn("pip install --upgrade requests==2.32.0", action.command_suggestion)


if __name__ == "__main__":
    unittest.main()
