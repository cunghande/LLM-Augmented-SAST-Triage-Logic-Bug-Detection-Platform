"""
Neo4j Graph Exporter for CPG (Code Property Graph)
===================================================
Xuất các dấu vết CPG (Entrypoint -> Guard -> Sink) vào Neo4j Graph Database.

Cấu hình mặc định:
  URI      : bolt://localhost:7687
  User     : neo4j
  Password : password123
"""

import os
from typing import List
from neo4j import GraphDatabase, Driver
from src.logic_bugs.ast_graph import TracePath


class Neo4jExporter:
    """Class hỗ trợ xuất CPG Code Graph vào Neo4j."""

    def __init__(
        self,
        uri: str = None,
        user: str = None,
        password: str = None
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "password123")
        self._driver: Driver = None

    def connect(self):
        """Khởi tạo kết nối tới Neo4j database."""
        self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        # Test connection
        with self._driver.session() as session:
            session.run("RETURN 1")
        print(f"[+] Connected successfully to Neo4j at {self.uri}")

    def close(self):
        """Đóng kết nối Neo4j driver."""
        if self._driver:
            self._driver.close()

    def clear_database(self, repo_name: str = None):
        """Xóa dữ liệu cũ của repository hoặc toàn bộ database."""
        if not self._driver:
            self.connect()

        with self._driver.session() as session:
            if repo_name:
                query = """
                MATCH (r:Repository {name: $repo_name})-[*0..]->(n)
                DETACH DELETE n, r
                """
                session.run(query, repo_name=repo_name)
                print(f"[+] Cleared existing graph for repository: {repo_name}")
            else:
                session.run("MATCH (n) DETACH DELETE n")
                print("[+] Cleared all nodes and relationships in Neo4j.")

    def export_traces(self, traces: List[TracePath], repo_name: str = "CN_WEB") -> int:
        """
        Xuất danh sách TracePath vào Neo4j dưới dạng Node và Relationship.
        
        Node labels:
          - Repository
          - File
          - Entrypoint
          - Guard
          - Sink

        Relationships:
          - (Repository)-[:CONTAINS_FILE]->(File)
          - (File)-[:DEFINES_ENTRYPOINT]->(Entrypoint)
          - (Entrypoint)-[:PROTECTED_BY]->(Guard)
          - (Entrypoint)-[:FLOWS_TO]->(Sink)
          - (Guard)-[:PERMITS_FLOW_TO]->(Sink)
        """
        if not self._driver:
            self.connect()

        inserted_count = 0

        cypher_query = """
        MERGE (repo:Repository {name: $repo_name})

        // Match or Create File Node
        MERGE (f:File {path: $file_path})
        MERGE (repo)-[:CONTAINS_FILE]->(f)

        // Create Entrypoint Node
        MERGE (e:Entrypoint {
            id: $entry_id,
            name: $entry_name,
            file_path: $file_path,
            line: $entry_line,
            snippet: $entry_snippet
        })
        MERGE (f)-[:DEFINES_ENTRYPOINT]->(e)

        // Create Sink Node
        MERGE (s:Sink {
            id: $sink_id,
            name: $sink_name,
            file_path: $sink_file,
            line: $sink_line,
            snippet: $sink_snippet
        })
        MERGE (e)-[:FLOWS_TO {has_auth_guard: $has_auth_guard}]->(s)

        // Create Guard Nodes if exists
        FOREACH (g_item IN $guards |
            MERGE (g:Guard {
                id: g_item.id,
                name: g_item.name,
                file_path: g_item.file_path,
                line: g_item.line,
                snippet: g_item.snippet
            })
            MERGE (e)-[:PROTECTED_BY]->(g)
            MERGE (g)-[:PERMITS_FLOW_TO]->(s)
        )
        """

        with self._driver.session() as session:
            for idx, trace in enumerate(traces):
                entry = trace.entrypoint
                sink = trace.sensitive_sink

                entry_id = f"{entry.file_path}:{entry.line_number}:{entry.name}"
                sink_id = f"{sink.file_path}:{sink.line_number}:{sink.name}"

                guards_data = [
                    {
                        "id": f"{g.file_path}:{g.line_number}:{g.name}",
                        "name": g.name,
                        "file_path": g.file_path,
                        "line": g.line_number,
                        "snippet": g.code_snippet
                    }
                    for g in trace.guards
                ]

                session.run(
                    cypher_query,
                    repo_name=repo_name,
                    file_path=entry.file_path,
                    entry_id=entry_id,
                    entry_name=entry.name,
                    entry_line=entry.line_number,
                    entry_snippet=entry.code_snippet,
                    sink_id=sink_id,
                    sink_name=sink.name,
                    sink_file=sink.file_path,
                    sink_line=sink.line_number,
                    sink_snippet=sink.code_snippet,
                    has_auth_guard=trace.has_auth_guard,
                    guards=guards_data
                )
                inserted_count += 1

        print(f"[OK] Exported {inserted_count} CPG traces to Neo4j graph DB.")
        return inserted_count
