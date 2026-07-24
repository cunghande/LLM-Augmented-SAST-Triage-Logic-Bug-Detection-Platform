"""
LLM-Augmented SAST Triage & Logic-Bug Detection Platform
=========================================================
Main entry point for the src package.

Multi-Agent Architecture:
  Agent 1 - SAST Triage Agent    : src/triage/engine.py
  Agent 2 - Logic-Bug Agent      : src/logic_bugs/detector.py
  Agent 3 - Risk & Remediation   : src/risk/scorer.py + src/remediation/generator.py
"""
