import unittest
from pathlib import Path
from src.logic_bugs.ast_graph import extract_code_graph


class TestASTGraph(unittest.TestCase):
    def test_extract_code_graph_cn_web(self):
        repo_dir = Path("repos/CN_WEB")
        if repo_dir.exists():
            traces = extract_code_graph(repo_dir)
            self.assertIsInstance(traces, list)
            print(f"\n[Test] Extracted {len(traces)} AST/CPG Code Graph traces from CN_WEB.")

    def test_extract_code_graph_sequential_recommender(self):
        repo_dir = Path("repos/Sequential-Recommender")
        if repo_dir.exists():
            traces = extract_code_graph(repo_dir)
            self.assertIsInstance(traces, list)
            print(f"\n[Test] Extracted {len(traces)} AST/CPG Code Graph traces from Sequential-Recommender.")


if __name__ == "__main__":
    unittest.main()
