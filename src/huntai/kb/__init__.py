"""Knowledge base — two DISTINCT mechanisms (do not conflate):

- CAG (`cag.py`): a bounded, STATIC methodology cheatsheet preloaded into a
  long-context model and reused via a stable cache key. No retrieval.
- Memory (`memory.py`): DYNAMIC per-session findings, retrieved on demand via
  hybrid BM25 + optional dense search.

CAG here is preloaded, cached context; it is deliberately kept separate from
retrieval (RAG) over session findings.
"""

from .cag import CAGStore
from .memory import FindingsMemory, bm25_scores

__all__ = ["CAGStore", "FindingsMemory", "bm25_scores"]
