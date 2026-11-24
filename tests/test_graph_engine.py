import unittest
from sbomsentry.core.graph_engine import DependencyGraphEngine
from sbomsentry.core.models import Component


class TestGraphEngine(unittest.TestCase):
    def test_dag_reachability_and_depth(self):
        components = [
            Component(name="my-app", version="1.0.0"),
            Component(name="requests", version="2.28.1"),
            Component(name="urllib3", version="1.26.5"),
        ]
        edges = {
            "my-app": ["requests"],
            "requests": ["urllib3"],
        }
        engine = DependencyGraphEngine("my-app", components, edges)
        direct, transitive = engine.get_statistics()
        self.assertEqual(direct, 2)  # my-app, requests
        self.assertEqual(transitive, 1)  # urllib3

        path = engine.get_shortest_path_from_root("urllib3")
        self.assertEqual(path, ["my-app", "requests", "urllib3"])


if __name__ == "__main__":
    unittest.main()
