"""Evaluation harness — measure HuntAI against known-answer labs.

Runs an assessment, compares findings to a ground-truth YAML, and reports
coverage (recall), precision over report-worthy findings, and F1 — a
falsifiable measure of the pipeline rather than an anecdotal one.
"""

from .harness import EvalHarness, Metrics, evaluate

__all__ = ["EvalHarness", "Metrics", "evaluate"]
