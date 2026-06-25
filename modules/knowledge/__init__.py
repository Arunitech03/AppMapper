"""Feature 8: Local knowledge base (SQLite FTS5, no cloud dependency)."""

from modules.knowledge.index import build_documents
from modules.knowledge.query import CANNED_QUERIES, to_fts_query

__all__ = ["build_documents", "to_fts_query", "CANNED_QUERIES"]
