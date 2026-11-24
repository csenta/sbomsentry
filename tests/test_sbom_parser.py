import os
import unittest
from sbomsentry.core.sbom_parser import SBOMParser


class TestSBOMParser(unittest.TestCase):
    def setUp(self):
        self.cyclonedx_path = "/home/emprogue/Projects/sbomsentry/examples/cyclonedx_sbom.json"
        self.req_path = "/home/emprogue/Projects/sbomsentry/examples/requirements.txt"
        self.lock_path = "/home/emprogue/Projects/sbomsentry/examples/package-lock.json"

    def test_parse_cyclonedx(self):
        self.assertTrue(os.path.isfile(self.cyclonedx_path))
        target_name, components, edges = SBOMParser.parse_file(self.cyclonedx_path)
        self.assertEqual(target_name, "enterprise-billing-service")
        self.assertEqual(len(components), 5)

        names = [c.name for c in components]
        self.assertIn("requests", names)
        self.assertIn("urllib3", names)
        self.assertIn("gpl-core-utility", names)
        self.assertIn("enterprise-billing-service", edges)

    def test_parse_requirements_txt(self):
        target_name, components, _ = SBOMParser.parse_file(self.req_path)
        self.assertEqual(len(components), 5)
        names = [c.name for c in components]
        self.assertIn("requests", names)
        self.assertIn("requsts", names)

    def test_parse_package_lock(self):
        target_name, components, edges = SBOMParser.parse_file(self.lock_path)
        self.assertEqual(target_name, "payment-portal")
        self.assertEqual(len(components), 2)
        names = [c.name for c in components]
        self.assertIn("lodash", names)
        self.assertIn("expres", names)


if __name__ == "__main__":
    unittest.main()
