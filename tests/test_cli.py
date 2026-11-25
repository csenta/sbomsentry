import argparse
import os
import tempfile
import unittest
from sbomsentry.cli import handle_graph, handle_remediate, handle_scan
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.cyclonedx_file = os.path.join(_ROOT, "examples", "cyclonedx_sbom.json")

    def test_cli_scan(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f_json:
            out_json = f_json.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f_html:
            out_html = f_html.name

        try:
            args = argparse.Namespace(
                input=self.cyclonedx_file,
                output_json=out_json,
                output_html=out_html,
                fail_on_cvss=0.0,
                fail_on_typosquat=False,
                allow_copyleft=False,
            )
            code = handle_scan(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
        finally:
            for p in (out_json, out_html):
                if os.path.exists(p):
                    os.remove(p)

    def test_cli_graph(self):
        args = argparse.Namespace(
            input=self.cyclonedx_file,
            target_component="urllib3",
        )
        code = handle_graph(args)
        self.assertEqual(code, 0)

    def test_cli_remediate(self):
        args = argparse.Namespace(
            input=self.cyclonedx_file,
        )
        code = handle_remediate(args)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
