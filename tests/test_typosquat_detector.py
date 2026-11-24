import unittest
from sbomsentry.analyzers.typosquat_detector import TyposquatDetector, homoglyph_check, levenshtein_distance
from sbomsentry.core.models import Component


class TestTyposquatDetector(unittest.TestCase):
    def test_levenshtein_distance(self):
        self.assertEqual(levenshtein_distance("requests", "requests"), 0)
        self.assertEqual(levenshtein_distance("requests", "requsts"), 1)
        self.assertEqual(levenshtein_distance("express", "expres"), 1)

    def test_homoglyph_detection(self):
        self.assertTrue(homoglyph_check("req_ests", "req-ests"))
        self.assertTrue(homoglyph_check("l0dash", "lodash"))

    def test_typosquat_analysis(self):
        components = [
            Component(name="requests", version="2.31.0"),
            Component(name="requsts", version="1.0.0"),
            Component(name="expres", version="4.17.1"),
            Component(name="custom-internal-lib", version="0.1.0"),
        ]
        detector = TyposquatDetector()
        findings = detector.analyze(components)

        detected_names = [f.component_name for f in findings]
        self.assertIn("requsts", detected_names)
        self.assertIn("expres", detected_names)
        self.assertNotIn("requests", detected_names)


if __name__ == "__main__":
    unittest.main()
