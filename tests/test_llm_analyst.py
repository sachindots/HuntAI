"""LLMAnalyst tests — remediation/summary enrichment + safe fallback."""

from huntai.agents import LLMAnalyst
from huntai.llm.client import LLMError
from huntai.schemas import Finding, Session, Severity


class FakeClient:
    def __init__(self, reply=None, raise_exc=None):
        self.reply, self.raise_exc = reply, raise_exc

    def complete(self, system, user, role=None, temperature=0.2):
        if self.raise_exc:
            raise self.raise_exc
        return self.reply


def _session():
    s = Session(name="t")
    s.findings = [Finding(title="DVWA Default Login", severity=Severity.HIGH, target="x")]
    return s


def test_enrich_applies_remediation():
    s = _session()
    fid = s.findings[0].id
    reply = f'{{"findings": {{"{fid}": {{"remediation": "Change default creds", "risk": "account takeover"}}}}}}'
    LLMAnalyst(FakeClient(reply)).enrich(s)
    assert s.findings[0].remediation == "Change default creds"
    assert "risk: account takeover" in s.findings[0].description
    # severity untouched by the LLM
    assert s.findings[0].severity is Severity.HIGH


def test_enrich_fallback_on_error():
    s = _session()
    before = s.findings[0].remediation
    LLMAnalyst(FakeClient(raise_exc=LLMError("no key"))).enrich(s)
    assert s.findings[0].remediation == before  # unchanged


def test_enrich_ignores_unknown_ids():
    s = _session()
    LLMAnalyst(FakeClient('{"findings": {"bogus": {"remediation": "x"}}}')).enrich(s)
    assert s.findings[0].remediation == ""


def test_executive_summary_text():
    report = {"targets": ["x"], "by_severity": {"high": 1, "info": 2}, "total_findings": 3}
    out = LLMAnalyst(FakeClient("Two-line exec summary.")).executive_summary(report)
    assert out == "Two-line exec summary."


def test_executive_summary_fallback():
    report = {"targets": ["x"], "by_severity": {"high": 1, "info": 2}, "total_findings": 3}
    out = LLMAnalyst(FakeClient(raise_exc=LLMError("down"))).executive_summary(report)
    assert "high" in out and "3 finding" in out
