"""Scope guard tests — the safety boundary must be airtight."""

import pytest

from huntai.scope import ScopeError, ScopeGuard

GUARD = ScopeGuard(
    allow_cidrs=["127.0.0.0/8", "10.13.37.0/24"],
    allow_domains=["localhost", ".huntai.lab", "dvwa.lab","https://aura-fest-hub.lovable.app"],
    deny_cidrs=["169.254.0.0/16"],
    lab_net="172.20.0.0/16",
    mode="lab",
    require_explicit_public=True,
)


# -- allowed -------------------------------------------------------------

@pytest.mark.parametrize("target", [
    "127.0.0.1",
    "172.20.0.5",          # lab net
    "10.13.37.9",
    "localhost",
    "dvwa.lab",
    "web.huntai.lab",      # suffix match
    "http://172.20.0.5:8080/app",
    "10.13.37.0/24",
    "https://aura-fest-hub.lovable.app",
])
def test_in_scope(target):
    assert GUARD.is_in_scope(target)


# -- denied --------------------------------------------------------------

@pytest.mark.parametrize("target", [
    "8.8.8.8",             # public ip
    "1.1.1.1",
    "169.254.169.254",     # cloud metadata (explicit deny)
    "example.com",         # unlisted domain
    "http://evil.com/x",
    "192.168.1.0/24",      # not in allow list
])
def test_out_of_scope(target):
    assert not GUARD.is_in_scope(target)


def test_deny_beats_allow():
    g = ScopeGuard(
        allow_cidrs=["169.254.0.0/16"],   # try to allow a denied range
        allow_domains=[],
        deny_cidrs=["169.254.0.0/16"],
        lab_net="172.20.0.0/16",
    )
    with pytest.raises(ScopeError):
        g.check("169.254.1.1")


def test_public_blocked_while_flag_true():
    with pytest.raises(ScopeError) as exc:
        GUARD.check("8.8.8.8")
    assert "public" in str(exc.value).lower()


def test_cidr_partial_out_of_scope_rejected():
    # a CIDR straddling in- and out-of-scope must be rejected
    with pytest.raises(ScopeError):
        GUARD.check("172.20.255.255/1")


def test_classify_kinds():
    assert GUARD.classify("10.0.0.1").kind.value == "ip"
    assert GUARD.classify("10.0.0.0/24").kind.value == "cidr"
    assert GUARD.classify("foo.lab").kind.value == "domain"
    assert GUARD.classify("https://x.lab/a").kind.value == "url"
