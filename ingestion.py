# heimdall/ingestion/__init__.py
"""
Ingestion module for Heimdall - A2A agent threat intelligence CLI tool.
This module provides the foundation for ingesting LangChain agent API traces
from LangSmith and normalizing them for behavioral threat analysis.
"""
from .langsmith_ingestion import (
    LangSmithTraceIngestor,
    ingest_langsmith_traces,
    save_normalized_traces
)

__all__ = [
    "LangSmithTraceIngestor",
    "ingest_langsmith_traces",
    "save_normalized_traces"
]