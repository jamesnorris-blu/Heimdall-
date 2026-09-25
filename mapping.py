import re
import json
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# --- 1. Verified MITRE ATLAS T-Codes ---
class ATLASTechnique(str, Enum):
    AML_T0051 = "AML.T0051"  # LLM Prompt Injection (Includes Indirect Injection)
    AML_T0054 = "AML.T0054"  # LLM Jailbreak Injection 
    AML_T0061 = "AML.T0061"  # AI Agent Tools (Unauthorized Usage)
    AML_T0062 = "AML.T0062"  # Exfiltration via AI Agent Tool Invocation

# --- 2. Internal Analysis Schema ---
class ToolCall(BaseModel):
    tool_name: str
    tool_arguments: Dict[str, Any]

class AgentEvent(BaseModel):
    trace_id: str
    timestamp: Optional[datetime] = None
    message_content: str  # Flattened string of all inputs/outputs for scanning
    tool_calls: List[ToolCall] = []

class ThreatAlert(BaseModel):
    trace_id: str
    technique_id: ATLASTechnique
    confidence_score: float = Field(ge=0.0, le=1.0)
    trigger_layer: str
    flagged_content: str
    notes: str

# --- 3. Adapter: Ingestion Output -> Analysis Input ---
def extract_agent_event(normalized_trace: Dict[str, Any]) -> AgentEvent:
    """
    Acts as an adapter between Paul's ingestion output and the detection engine.
    Flattens message content and extracts distinct tool calls from spans.
    """
    trace_id = normalized_trace.get("trace_id", "UNKNOWN")
    
    # Safely parse timestamp
    start_time_str = normalized_trace.get("start_time")
    timestamp = None
    if start_time_str:
        try:
            # Handle ISO format strings typically returned by LangSmith (we'll confirm this l8ter)
            timestamp = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
        except ValueError:
            pass

    # 1. Extract Tool Calls from Spans
    tool_calls = []
    spans = normalized_trace.get("spans", [])
    for span in spans:
        if span.get("span_type") == "tool":
            tool_calls.append(ToolCall(
                tool_name=span.get("name", "unknown_tool"),
                tool_arguments=span.get("inputs", {})
            ))

    # 2. Flatten Content for Injection Scanning
    # we aggregate inputs/outputs from the main trace and all LLM spans (hopefully)
    content_fragments = []
    
    main_inputs = normalized_trace.get("inputs", {})
    main_outputs = normalized_trace.get("outputs", {})
    if main_inputs: content_fragments.append(json.dumps(main_inputs))
    if main_outputs: content_fragments.append(json.dumps(main_outputs))

    for span in spans:
        if span.get("span_type") in ["llm", "chat_model", "chain"]:
            if span.get("inputs"): content_fragments.append(json.dumps(span.get("inputs")))
            if span.get("outputs"): content_fragments.append(json.dumps(span.get("outputs")))

    message_content = " | ".join(content_fragments)

    return AgentEvent(
        trace_id=trace_id,
        timestamp=timestamp,
        message_content=message_content,
        tool_calls=tool_calls
    )

# --- 4. Layer 1: Heuristic Detection Engine ---
class HeuristicDetectionEngine:
    def __init__(self):
        # Base regex patterns for fast, local evaluation
        self.injection_signatures = [
            r"(?i)ignore\s+all\s+previous\s+instructions",
            r"(?i)system\s+prompt",
            r"(?i)you\s+are\s+now\s+(?:acting\s+as)?",
            r"(?i)override\s+directives"
        ]
        self.exfiltration_signatures = [
            r"(?i)curl\s+-X\s+POST",
            r"(?i)wget\s+",
            r"(?i)export\s+to\s+(?:http|ftp)"
        ]

    def analyze_event(self, event: AgentEvent) -> Optional[ThreatAlert]:
        """Scans a flattened AgentEvent against heuristic signatures."""
        
        # 1. Check for AML.T0051 / AML.T0054 (Injection & Jailbreak in payload)
        for pattern in self.injection_signatures:
            if re.search(pattern, event.message_content):
                return ThreatAlert(
                    trace_id=event.trace_id,
                    technique_id=ATLASTechnique.AML_T0051,
                    confidence_score=0.85,
                    trigger_layer="Heuristics",
                    flagged_content=event.message_content[:200] + "...", # Truncate for output
                    notes=f"Matched injection signature: {pattern}"
                )

        # 2. Check for AML.T0061 / AML.T0062 (Rogue Tool Invocation & Exfil)
        for tool in event.tool_calls:
            # Flagging potentially dangerous native tool calls passed between agents
            if tool.tool_name in ["execute_shell", "run_script", "python_repl"]:
                 return ThreatAlert(
                    trace_id=event.trace_id,
                    technique_id=ATLASTechnique.AML_T0061,
                    confidence_score=0.90,
                    trigger_layer="Heuristics",
                    flagged_content=tool.tool_name,
                    notes="Unauthorized system-level tool invocation detected."
                )
            
            # Check arguments for exfiltration patterns
            # Flatten arguments dictionary to a single string for regex scanning
            args_string = json.dumps(tool.tool_arguments)
            for pattern in self.exfiltration_signatures:
                if re.search(pattern, args_string):
                    return ThreatAlert(
                        trace_id=event.trace_id,
                        technique_id=ATLASTechnique.AML_T0062,
                        confidence_score=0.95,
                        trigger_layer="Heuristics",
                        flagged_content=args_string[:100] + "...",
                        notes=f"Exfiltration pattern detected in tool argument: {pattern}"
                    )

        return None