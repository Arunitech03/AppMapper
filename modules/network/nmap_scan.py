"""Module 6: Nmap service discovery.

Wraps the ``nmap`` CLI to perform **safe service/version discovery only**
(``-sV``). It explicitly does NOT run NSE vulnerability scripts (``--script`` /
``-sC``) and performs no exploitation. If the ``nmap`` binary is not installed,
the module degrades gracefully (logs a warning and returns an empty result).
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import xml.etree.ElementTree as ET

from core.base import BaseModule
from models.schemas import ModuleResult, NetworkService, ScanContext

# Conservative default: top common ports, version detection, no scripts.
DEFAULT_ARGS = ["-sV", "-T3", "--top-ports", "100", "-oX", "-"]


class NmapModule(BaseModule):
    name = "nmap"
    category = "network"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        if shutil.which("nmap") is None:
            self.log.warning("nmap.not_installed", hint="install nmap to enable service discovery")
            return ModuleResult(
                module=self.name, ok=True, error="nmap binary not found", data=[], items=0
            )

        host = ctx.target.host
        xml_output = await asyncio.to_thread(self._run_nmap, host, ctx.timeout)
        services = self._parse(xml_output) if xml_output else []
        return ModuleResult(
            module=self.name, data=[s.model_dump() for s in services], items=len(services)
        )

    def _run_nmap(self, host: str, timeout: float) -> str | None:
        cmd = ["nmap", *DEFAULT_ARGS, host]
        # Guardrail: never allow script/exploit flags through.
        forbidden = {"--script", "-sC", "-A", "--script-args"}
        if forbidden & set(cmd):
            raise ValueError("refusing to run nmap with script/exploit flags")
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(timeout * 30, 120),
                check=False,
            )
            if proc.returncode != 0:
                self.log.warning(
                    "nmap.nonzero_exit", code=proc.returncode, stderr=proc.stderr[:200]
                )
            return proc.stdout
        except (subprocess.SubprocessError, OSError) as exc:
            self.log.warning("nmap.run_failed", error=str(exc))
            return None

    def _parse(self, xml_output: str) -> list[NetworkService]:
        services: list[NetworkService] = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            self.log.warning("nmap.parse_failed", error=str(exc))
            return services

        for port in root.iterfind(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port.find("service")
            version = None
            service_name = None
            if svc is not None:
                service_name = svc.get("name")
                version = " ".join(p for p in (svc.get("product"), svc.get("version")) if p) or None
            services.append(
                NetworkService(
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    service=service_name,
                    version=version,
                    state="open",
                )
            )
        return services
