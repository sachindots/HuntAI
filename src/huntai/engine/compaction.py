"""Context compaction + token accounting.

The whole point: never feed raw tool dumps back to the LLM. We feed the compact
`ToolResult.summary` fields, batched. `TokenBudget` tracks rough spend so an
assessment can't silently blow up cost.
"""

from __future__ import annotations

from ..schemas import ToolResult


def estimate_tokens(text: str) -> int:
    """Rough heuristic: ~4 chars/token. Good enough for budgeting."""
    return max(1, len(text) // 4)


def compact_results(results: list[ToolResult]) -> str:
    """Turn a batch of finished tool results into one short digest for the LLM.
    Uses summaries only — raw output stays on disk (`raw_ref`)."""
    lines = []
    for r in results:
        status = r.status.value
        lines.append(f"- [{r.tool}] {status}: {r.summary}")
    return "\n".join(lines)


class TokenBudget:
    def __init__(self, limit: int = 200_000) -> None:
        self.limit = limit
        self.spent = 0

    def charge(self, text: str) -> int:
        cost = estimate_tokens(text)
        self.spent += cost
        return cost

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.spent >= self.limit
