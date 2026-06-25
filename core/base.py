"""Plugin base class for discovery modules.

Every module subclasses :class:`BaseModule`, declares a ``name`` and ``category``,
and implements an async :meth:`run`. This uniform contract is what makes the
framework extensible for Tier 2/3: new capabilities are added by dropping in a
new ``BaseModule`` subclass and registering it (see ``core.registry``).
"""

from __future__ import annotations

import abc

from core.logging import get_logger
from models.schemas import ModuleResult, ScanContext


class BaseModule(abc.ABC):
    """Abstract base for all discovery/analysis modules."""

    #: Unique, stable identifier (used in CLI toggles and reports).
    name: str = "base"
    #: Logical grouping (recon | fingerprint | ssl | frontend | network | api).
    category: str = "generic"

    def __init__(self) -> None:
        self.log = get_logger(self.name)

    @abc.abstractmethod
    async def run(self, ctx: ScanContext) -> ModuleResult:
        """Execute the module against the target described by ``ctx``."""
        raise NotImplementedError

    async def safe_run(self, ctx: ScanContext) -> ModuleResult:
        """Run the module, converting unexpected errors into a failed result.

        This keeps one failing module from aborting an entire scan.
        """
        try:
            result = await self.run(ctx)
            self.log.info("module.complete", module=self.name, items=result.items, ok=result.ok)
            return result
        except Exception as exc:  # noqa: BLE001 - boundary: never let a module crash the scan
            self.log.error("module.error", module=self.name, error=str(exc))
            return ModuleResult(module=self.name, ok=False, error=str(exc), items=0)
