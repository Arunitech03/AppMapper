"""Module registry.

Maps stable module names to :class:`~core.base.BaseModule` subclasses so the
orchestrator and CLI can enumerate, select, and skip modules by name. Adding a
Tier 2/3 module is a one-line registration here.
"""

from __future__ import annotations

from collections.abc import Iterable

from core.base import BaseModule
from modules.api.discovery import ApiDiscoveryModule
from modules.fingerprint.techstack import TechStackModule
from modules.frontend.js_analysis import JSAnalysisModule
from modules.network.nmap_scan import NmapModule
from modules.recon.directories import DirectoryEnumModule
from modules.recon.subdomains import SubdomainModule
from modules.ssl.ssl_scanner import SSLModule

# Registration order is also the default execution order.
_MODULE_CLASSES: tuple[type[BaseModule], ...] = (
    SubdomainModule,
    DirectoryEnumModule,
    TechStackModule,
    SSLModule,
    JSAnalysisModule,
    NmapModule,
    ApiDiscoveryModule,
)


def all_module_names() -> list[str]:
    return [cls.name for cls in _MODULE_CLASSES]


def build_modules(skip: Iterable[str] | None = None) -> list[BaseModule]:
    """Instantiate all registered modules except those whose name is in ``skip``."""
    skip_set = {s.strip().lower() for s in (skip or [])}
    return [cls() for cls in _MODULE_CLASSES if cls.name.lower() not in skip_set]
