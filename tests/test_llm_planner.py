"""LLMPlanner tests — untrusted-output validation + safe fallback. A fake LLM
client stands in for the network so no litellm/keys are needed."""

from huntai.agents import LLMPlanner, RuleBasedPlanner
from huntai.agents.llm_planner import _clean_opts, _extract_json
from huntai.llm.client import LLMError
from huntai.tools import default_registry


class FakeClient:
    def __init__(self, reply=None, raise_exc=None):
        self.reply = reply
        self.raise_exc = raise_exc

    def complete(self, system, user, role=None, temperature=0.2):
        if self.raise_exc:
            raise self.raise_exc
        return self.reply


def _planner(client):
    return LLMPlanner(default_registry(), client=client)


def test_valid_plan_parsed():
    reply = '{"plan":[{"tool":"subfinder"},{"tool":"nmap","opts":{"ports":"80"}},{"tool":"httpx"}]}'
    steps = _planner(FakeClient(reply)).plan("scanme.huntai.lab")
    names = [s.tool for s in steps]
    assert names[0] == "subfinder"          # passive forced first
    assert "nmap" in names and "httpx" in names
    nmap = next(s for s in steps if s.tool == "nmap")
    assert nmap.opts == {"ports": "80"}


def test_unknown_tool_dropped():
    # model tries to inject a dangerous / unknown tool -> ignored
    reply = '{"plan":[{"tool":"rm -rf"},{"tool":"metasploit"},{"tool":"nmap"}]}'
    steps = _planner(FakeClient(reply)).plan("172.20.0.10")
    assert [s.tool for s in steps] == ["nmap"]


def test_bad_opts_filtered():
    reply = '{"plan":[{"tool":"nuclei","opts":{"severity":"pwn","extra":"x"}}]}'
    steps = _planner(FakeClient(reply)).plan("172.20.0.10")
    assert steps[0].opts == {}  # invalid severity + unknown key dropped


def test_fallback_on_llm_error():
    steps = _planner(FakeClient(raise_exc=LLMError("no key"))).plan("172.20.0.10")
    # falls back to rule-based chain
    assert [s.tool for s in steps] == [s.tool for s in RuleBasedPlanner().plan("172.20.0.10")]


def test_fallback_on_bad_json():
    steps = _planner(FakeClient("not json at all")).plan("172.20.0.10")
    assert steps  # rule-based fallback produced a plan


def test_fallback_on_empty_plan():
    steps = _planner(FakeClient('{"plan":[]}')).plan("172.20.0.10")
    assert len(steps) == len(RuleBasedPlanner().plan("172.20.0.10"))


def test_extract_json_from_fenced():
    assert _extract_json('```json\n{"plan":[]}\n```') == '{"plan":[]}'


def test_clean_opts_coerces():
    assert _clean_opts("naabu", {"top_ports": "50"}) == {"top_ports": 50}
    assert _clean_opts("nmap", {"bad": "x"}) == {}
