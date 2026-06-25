"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from models.schemas import ScanContext, TargetInput


@pytest.fixture
def ctx_factory():
    """Return a factory that builds a ScanContext for a given URL."""

    def make(url: str = "http://testserver.local", **kwargs) -> ScanContext:
        target = TargetInput(url=url, domain=kwargs.pop("domain", "testserver.local"))
        return ScanContext(
            target=target, timeout=2.0, max_concurrency=5, verify_tls=False, **kwargs
        )

    return make


@pytest.fixture
def memory_db():
    """An in-memory SQLite Database instance."""
    from storage.database import Database

    return Database("sqlite:///:memory:")
