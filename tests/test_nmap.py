"""Tests for Module 6: nmap integration (XML parsing + graceful degradation)."""

from __future__ import annotations

from modules.network import nmap_scan
from modules.network.nmap_scan import NmapModule

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_open_ports_only():
    services = NmapModule()._parse(SAMPLE_XML)
    ports = {s.port: s for s in services}
    assert set(ports) == {443, 80}  # closed 22 excluded
    assert ports[443].service == "https"
    assert ports[443].version == "nginx 1.25.0"


async def test_graceful_when_nmap_missing(ctx_factory, monkeypatch):
    monkeypatch.setattr(nmap_scan.shutil, "which", lambda _: None)
    result = await NmapModule().run(ctx_factory(url="http://testserver.local"))
    assert result.ok is True
    assert result.items == 0
    assert "not found" in (result.error or "")
