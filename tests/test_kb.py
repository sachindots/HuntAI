"""KB tests — CAG preload + hybrid findings memory. CAG and memory stay
separate."""

from pathlib import Path

from huntai.kb import CAGStore, FindingsMemory, bm25_scores
from huntai.schemas import Finding, Severity

ROOT = Path(__file__).resolve().parents[1]


# -- CAG ----------------------------------------------------------------

def test_cag_loads_kb():
    cag = CAGStore(ROOT / "kb").load()
    assert "Reconnaissance Methodology" in cag.context
    assert "Common Ports" in cag.context
    assert cag.token_estimate() > 0


def test_cag_key_stable_and_content_addressed():
    a = CAGStore(ROOT / "kb").load().cache_key
    b = CAGStore(ROOT / "kb").load().cache_key
    assert a == b and len(a) == 16


# -- memory (BM25 only) -------------------------------------------------

def test_bm25_ranks_relevant_first():
    docs = [
        "open port 22 ssh OpenSSH weak credentials",
        "http title DVWA apache php login page",
        "smtp mail server relay",
    ]
    scores = bm25_scores("dvwa apache login", docs)
    assert scores[1] == max(scores)


def test_memory_retrieve_relevant():
    mem = FindingsMemory()
    mem.add_finding(Finding(title="DVWA default login admin/password",
                            severity=Severity.HIGH, target="172.20.0.10"))
    mem.add_finding(Finding(title="open 22/tcp ssh", severity=Severity.INFO,
                            target="172.20.0.10"))
    top = mem.retrieve("default credentials web login", k=1)
    assert "DVWA" in top[0].text


def test_memory_empty():
    assert FindingsMemory().retrieve("anything") == []


# -- memory (hybrid with fake embedder) ---------------------------------

def test_hybrid_with_embedder():
    # toy embedder: char-histogram vector — enough to exercise RRF path
    def embed(text: str) -> list[float]:
        v = [0.0] * 26
        for ch in text.lower():
            if "a" <= ch <= "z":
                v[ord(ch) - 97] += 1
        return v

    mem = FindingsMemory(embedder=embed)
    mem.add("1", "sql injection on id parameter")
    mem.add("2", "cross site scripting reflected xss")
    mem.add("3", "open ssh port weak password")
    top = mem.retrieve("sql injection parameter", k=1)
    assert top[0].id == "1"
