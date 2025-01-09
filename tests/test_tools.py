"""Tool parser tests — run on saved fixtures, no network/docker."""

from pathlib import Path

from huntai.tools import default_registry
from huntai.tools.nmap import Nmap
from huntai.tools.pdtools import Httpx, Naabu, Nuclei, Subfinder

FIX = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def test_nmap_parse():
    r = Nmap().parse(_read("nmap.xml"), "172.20.0.10")
    assert r.parsed["open_ports"] == 2  # closed 443 excluded
    ports = {p["port"]: p for h in r.parsed["hosts"] for p in h["ports"]}
    assert ports[80]["product"] == "Apache httpd"
    assert ports[22]["service"] == "ssh"
    assert "2 open" in r.summary


def test_httpx_parse():
    r = Httpx().parse(_read("httpx.jsonl"), "172.20.0.10")
    assert len(r.parsed["services"]) == 2
    assert "PHP" in r.parsed["tech"]


def test_naabu_parse():
    r = Naabu().parse(_read("naabu.jsonl"), "172.20.0.10")
    assert r.parsed["ports"] == [22, 80]


def test_nuclei_parse():
    r = Nuclei().parse(_read("nuclei.jsonl"), "172.20.0.10")
    assert r.parsed["by_severity"]["high"] == 1
    assert len(r.parsed["vulns"]) == 2


def test_subfinder_dedup():
    r = Subfinder().parse(_read("subfinder.jsonl"), "huntai.lab")
    assert r.parsed["subdomains"] == ["admin.huntai.lab", "api.huntai.lab"]


def test_summary_is_compact():
    # summary must never inline raw output (token discipline)
    r = Nmap().parse(_read("nmap.xml"), "172.20.0.10")
    assert len(r.summary) < 300
    assert "<port" not in r.summary


def test_registry_partitions():
    reg = default_registry()
    assert reg.get("subfinder").passive is True
    assert {t.name for t in reg.passive()} == {"subfinder"}
    assert "nmap" in {t.name for t in reg.active()}


def test_build_argv():
    assert Nmap().build_argv("172.20.0.10", ports="80,443")[:2] == ["nmap", "-sV"]
    assert "-p" in Nmap().build_argv("x", ports="80")
    assert Subfinder().build_argv("huntai.lab")[0] == "subfinder"
