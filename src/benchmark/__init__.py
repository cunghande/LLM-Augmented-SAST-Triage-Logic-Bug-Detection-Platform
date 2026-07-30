"""
Benchmark Evaluation Framework Package (Metric 2.0)
==================================================
Provides benchmark ground-truth matching adapters, Metric 2.0 evaluation engine,
run integrity tracking, latency measurement, and reporting.
"""

from src.benchmark.adapters import (
    AdapterMatchReport,
    MatchType,
    OWASPBenchmarkJavaAdapter,
    OWASPBenchmarkPythonAdapter,
    SamsungCredDataAdapter,
    RealVulnBenchmarkAdapter,
    get_adapter_for_benchmark,
)
from src.benchmark.evaluator import (
    BenchmarkEvaluator,
    EvaluationMetrics,
    EvaluationRun,
)
from src.benchmark.reporter import BenchmarkReportGenerator

__all__ = [
    "AdapterMatchReport",
    "MatchType",
    "OWASPBenchmarkJavaAdapter",
    "OWASPBenchmarkPythonAdapter",
    "SamsungCredDataAdapter",
    "RealVulnBenchmarkAdapter",
    "get_adapter_for_benchmark",
    "BenchmarkEvaluator",
    "EvaluationMetrics",
    "EvaluationRun",
    "BenchmarkReportGenerator",
]
