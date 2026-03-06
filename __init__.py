"""
AgentGuard: Real-time prompt injection detection for AI agents

Protects against Clinejection-style attacks, command injection, and malicious 
prompt manipulation. Works as both OpenClaw skill and Claude MCP server.
"""

from .agent_guard import AgentGuard, ThreatLevel, DetectionResult

__version__ = "1.0.0"
__all__ = ["AgentGuard", "ThreatLevel", "DetectionResult"]