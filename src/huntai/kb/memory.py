"""Findings memory — dynamic, retrieved on demand.

Hybrid retrieval: pure-python BM25 (always) fused with optional dense
embeddings (Ollama bge-m3 via an injected embedder) using reciprocal rank
fusion. No heavy deps required for the BM25 path, so it runs offline and in
tests. This is RAG over session findings — explicitly separate from CAG.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Sequence

_TOKEN = re.compile(r"[a-z0-9]+")


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def bm25_scores(query: str, docs: Sequence[str], k1: float = 1.5, b: float = 0.75) -> list[float]:
    """Classic BM25 over a small corpus."""
    corpus = [_tokenize(d) for d in docs]
    n = len(corpus)
    if n == 0:
        return []
    avgdl = sum(len(d) for d in corpus) / n
    # document frequency
    df: dict[str, int] = {}
    for doc in corpus:
        for term in set(doc):
            df[term] = df.get(term, 0) + 1
    scores = [0.0] * n
    for term in set(_tokenize(query)):
        if term not in df:
            continue
        idf = math.log(1 + (n - df[term] + 0.5) / (df[term] + 0.5))
        for i, doc in enumerate(corpus):
            tf = doc.count(term)
            if tf == 0:
                continue
            denom = tf + k1 * (1 - b + b * len(doc) / avgdl)
            scores[i] += idf * (tf * (k1 + 1)) / denom
    return scores


def _rank(scores: list[float]) -> dict[int, int]:
    """index -> rank (1 = best)."""
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    return {idx: r + 1 for r, idx in enumerate(order)}


# embedder: text -> vector. Optional; None => BM25 only.
Embedder = Callable[[str], list[float]]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


@dataclass
class MemoryDoc:
    id: str
    text: str
    meta: dict = field(default_factory=dict)
    vector: list[float] | None = None


class FindingsMemory:
    def __init__(self, embedder: Embedder | None = None) -> None:
        self.embedder = embedder
        self.docs: list[MemoryDoc] = []

    def add(self, id: str, text: str, **meta) -> None:
        vec = self.embedder(text) if self.embedder else None
        self.docs.append(MemoryDoc(id=id, text=text, meta=meta, vector=vec))

    def add_finding(self, finding) -> None:
        text = f"{finding.title} {finding.description} {finding.evidence} {finding.target}"
        self.add(finding.id, text, severity=finding.severity.value, target=finding.target)

    def retrieve(self, query: str, k: int = 5) -> list[MemoryDoc]:
        if not self.docs:
            return []
        texts = [d.text for d in self.docs]
        bm = bm25_scores(query, texts)
        bm_rank = _rank(bm)

        if self.embedder is not None:
            qv = self.embedder(query)
            dense = [_cosine(qv, d.vector or []) for d in self.docs]
            dv_rank = _rank(dense)
            # reciprocal rank fusion
            fused = {i: 1 / (60 + bm_rank[i]) + 1 / (60 + dv_rank[i])
                     for i in range(len(self.docs))}
        else:
            fused = {i: 1 / (60 + bm_rank[i]) for i in range(len(self.docs))}

        best = sorted(range(len(self.docs)), key=lambda i: fused[i], reverse=True)
        return [self.docs[i] for i in best[:k]]
