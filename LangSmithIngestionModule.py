# heimdall/ingestion/langsmith_ingestion.py
"""
LangSmith trace ingestion module for Heimdall.
Handles ingestion of LangChain agent API traces from LangSmith,
normalizing them into a structured schema for threat analysis.
"""
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urljoin

from heimdall.config import HeimdallConfig

logger = logging.getLogger(__name__)


class LangSmithTraceIngestor:
    """
    Ingestor for LangSmith traces that normalizes them into a structured schema.
    Handles connection to LangSmith API, fetching traces, and normalizing
    them into a consistent format for downstream processing.
    """
    
    def __init__(self, config: HeimdallConfig):
        self.config = config
        self.session = self._create_session()
        self.base_url = config.langsmith_api_url
    
    def _create_session(self) -> requests.Session:
        """Create configured requests session with retry strategy."""
        session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=self.config.langsmith_max_retries,
            pool_connections=self.config.langsmith_pool_connections,
            pool_maxsize=self.config.langsmith_pool_maxsize
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def fetch_traces(
        self,
        trace_ids: Optional[List[str]] = None,
        project_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Fetch traces from LangSmith API with pagination.
        Handles single run and batch run fetching.
        """
        logger.info("Fetching traces from LangSmith")
        
        # Single run optimization
        if trace_ids and len(trace_ids) == 1:
            run_id = trace_ids[0]
            try:
                response = self.session.get(
                    urljoin(self.base_url, f"/api/v1/runs/{run_id}"),
                    headers={"Authorization": f"Bearer {self.config.langsmith_api_key}"},
                    timeout=self.config.langsmith_timeout
                )
                response.raise_for_status()
                traces_data = [response.json()]
                logger.info("Fetched 1 trace from LangSmith")
                return self._normalize_traces(traces_data)
            except requests.RequestException as e:
                logger.error(f"Failed to fetch single trace {run_id}: {e}")
                raise

        # Batch fetch with pagination
        params = {}
        if trace_ids:
            params["trace_ids"] = ",".join(trace_ids)
        if project_name:
            params["project_name"] = project_name
        if start_time:
            params["start_time"] = start_time.isoformat()
        if end_time:
            params["end_time"] = end_time.isoformat()
        
        all_traces = []
        offset = 0
        page_size = min(100, limit)
        
        try:
            while len(all_traces) < limit:
                params["limit"] = min(page_size, limit - len(all_traces))
                params["offset"] = offset

                response = self.session.get(
                    urljoin(self.base_url, "/api/v1/runs"),
                    headers={"Authorization": f"Bearer {self.config.langsmith_api_key}"},
                    params=params,
                    timeout=self.config.langsmith_timeout
                )
                response.raise_for_status()
                traces_data = response.json()
                
                if not traces_data:
                    break
                    
                all_traces.extend(traces_data)
                logger.info(f"Fetched page with {len(traces_data)} traces. Total: {len(all_traces)}")
                
                if len(traces_data) < params["limit"]:
                    break
                    
                offset += len(traces_data)
            
            logger.info(f"Fetched {len(all_traces)} total traces from LangSmith")
            return self._normalize_traces(all_traces)
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch traces: {e}")
            raise
    
    def _fetch_child_runs(self, run_id: str) -> List[Dict[str, Any]]:
        """
        Fetch child runs (spans) for a given parent run.
        Returns empty list if fetch fails — never breaks parent normalization.
        """
        if not run_id:
            return []
        try:
            response = self.session.get(
                urljoin(self.base_url, "/api/v1/runs"),
                headers={"Authorization": f"Bearer {self.config.langsmith_api_key}"},
                params={"parent_run_id": run_id},
                timeout=self.config.langsmith_timeout
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch child runs for parent {run_id}: {e}")
            return []
            
    def _normalize_traces(self, traces_data: List[Dict]) -> List[Dict[str, Any]]:
        """
        Normalize batch of traces.
        Isolates failures per trace — one bad trace never kills the batch.
        """
        normalized_traces = []
        for trace in traces_data:
            try:
                normalized_trace = self._normalize_single_trace(trace)
                normalized_traces.append(normalized_trace)
            except Exception as e:
                trace_id = trace.get("id", "UNKNOWN_ID")
                logger.error(f"Failed to normalize trace {trace_id}: {e}")
                continue
        return normalized_traces
    
    def _normalize_single_trace(self, trace_data: Dict) -> Dict[str, Any]:
        """
        Normalize a single trace into structured schema.
        Fetches child runs separately — LangSmith does not nest them.
        """
        normalized_trace = {
            "trace_id": trace_data.get("id"),
            "project_name": trace_data.get("session_name"),
            "trace_name": trace_data.get("name"),
            "start_time": trace_data.get("start_time"),
            "end_time": trace_data.get("end_time"),
            "duration": trace_data.get("total_duration"),
            "status": trace_data.get("status"),
            "inputs": trace_data.get("inputs", {}),
            "outputs": trace_data.get("outputs", {}),
            "metadata": trace_data.get("metadata", {}),
            "spans": [],
            "created_at": datetime.now().isoformat()
        }
        
        trace_id = trace_data.get("id")
        spans = self._fetch_child_runs(trace_id) if trace_id else []
        normalized_trace["spans"] = [self._normalize_span(span) for span in spans]
        
        return normalized_trace
    
    def _normalize_span(self, span_data: Dict) -> Dict[str, Any]:
        """Normalize a single child run (span) into structured format."""
        return {
            "span_id": span_data.get("id"),
            "trace_id": span_data.get("trace_id"),
            "name": span_data.get("name"),
            "span_type": span_data.get("span_type"),
            "start_time": span_data.get("start_time"),
            "end_time": span_data.get("end_time"),
            "duration": span_data.get("total_duration"),
            "status": span_data.get("status"),
            "inputs": span_data.get("inputs", {}),
            "outputs": span_data.get("outputs", {}),
            "metadata": span_data.get("metadata", {}),
            "parent_span_id": span_data.get("parent_span_id"),
            "tags": span_data.get("tags", [])
        }


def ingest_langsmith_traces(
    config: HeimdallConfig,
    trace_ids: Optional[List[str]] = None,
    project_name: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """Public interface — instantiates ingestor and fetches traces."""
    ingestor = LangSmithTraceIngestor(config)
    return ingestor.fetch_traces(
        trace_ids=trace_ids,
        project_name=project_name,
        start_time=start_time,
        end_time=end_time,
        limit=limit
    )


def save_normalized_traces(traces: List[Dict[str, Any]], output_path: str) -> None:
    """Serialize normalized traces to JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(traces, f, indent=2, ensure_ascii=False)
    logger.info(f"Saved {len(traces)} normalized traces to {output_path}")