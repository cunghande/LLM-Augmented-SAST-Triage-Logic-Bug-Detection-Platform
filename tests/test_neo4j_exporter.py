import unittest
from src.logic_bugs.ast_graph import CodeNode, TracePath
from src.logic_bugs.neo4j_exporter import Neo4jExporter


class TestNeo4jExporter(unittest.TestCase):

    def test_neo4j_connection(self):
        """Test connecting to local Neo4j instance in Docker."""
        exporter = Neo4jExporter()
        try:
            exporter.connect()
            self.assertIsNotNone(exporter._driver)
            exporter.close()
        except Exception as e:
            self.skipTest(f"Neo4j container not available: {e}")

    def test_export_single_trace(self):
        """Test exporting a sample trace to Neo4j."""
        exporter = Neo4jExporter()
        try:
            exporter.connect()
        except Exception as e:
            self.skipTest(f"Neo4j container not available: {e}")

        sample_trace = TracePath(
            entrypoint=CodeNode(
                node_type="ENTRYPOINT",
                name="GET /test/route",
                file_path="test/route.js",
                line_number=10,
                code_snippet="router.get('/test/route', getTestData)"
            ),
            guards=[
                CodeNode(
                    node_type="GUARD",
                    name="AuthMiddleware",
                    file_path="test/route.js",
                    line_number=10,
                    code_snippet="authenticate"
                )
            ],
            sensitive_sink=CodeNode(
                node_type="SINK",
                name="User.findById",
                file_path="test/controller.js",
                line_number=25,
                code_snippet="await User.findById(id)"
            ),
            has_auth_guard=True
        )

        count = exporter.export_traces([sample_trace], repo_name="TEST_REPO")
        self.assertEqual(count, 1)

        # Cleanup test repo
        exporter.clear_database(repo_name="TEST_REPO")
        exporter.close()


if __name__ == "__main__":
    unittest.main()
