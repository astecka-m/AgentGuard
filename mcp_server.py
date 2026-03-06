#!/usr/bin/env python3
"""
AgentGuard MCP Server for Claude integration
"""

import json
import sys
from typing import Any, Dict, List, Optional
from agent_guard import AgentGuard, ThreatLevel

class MCPServer:
    """Model Context Protocol server for AgentGuard"""
    
    def __init__(self):
        self.guard = AgentGuard()
        self.tools = [
            {
                "name": "agent_guard_analyze",
                "description": "Analyze text for security threats including prompt injection and command execution",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to analyze for security threats"
                        },
                        "context": {
                            "type": "string", 
                            "description": "Context for analysis (general, github_title, github_body)",
                            "default": "general"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "agent_guard_sanitize", 
                "description": "Sanitize dangerous content from text by replacing threats with safe placeholders",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to sanitize"
                        }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "agent_guard_github_issue",
                "description": "Analyze GitHub issue for Clinejection-style attacks and malicious content",
                "inputSchema": {
                    "type": "object", 
                    "properties": {
                        "title": {
                            "type": "string",
                            "description": "GitHub issue title"
                        },
                        "body": {
                            "type": "string",
                            "description": "GitHub issue body content"
                        }
                    },
                    "required": ["title", "body"]
                }
            },
            {
                "name": "agent_guard_report",
                "description": "Generate security analytics report from recent analyses",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "description": "Report format (summary, detailed, json)",
                            "default": "summary"
                        }
                    }
                }
            }
        ]
    
    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP request"""
        method = request.get("method")
        
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "agent-guard",
                        "version": "1.0.0"
                    }
                }
            }
        
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0", 
                "id": request.get("id"),
                "result": {
                    "tools": self.tools
                }
            }
        
        elif method == "tools/call":
            return self._handle_tool_call(request)
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"), 
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
    
    def _handle_tool_call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle tool call request"""
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        
        try:
            if tool_name == "agent_guard_analyze":
                result = self._analyze_text(arguments)
            elif tool_name == "agent_guard_sanitize":
                result = self._sanitize_text(arguments)
            elif tool_name == "agent_guard_github_issue":
                result = self._analyze_github_issue(arguments)
            elif tool_name == "agent_guard_report":
                result = self._generate_report(arguments)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {
                        "code": -32602,
                        "message": f"Unknown tool: {tool_name}"
                    }
                }
            
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str)
                        }
                    ]
                }
            }
            
        except Exception as e:
            # Log error internally but don't expose implementation details
            print(f"Internal error: {str(e)}", file=sys.stderr)
            return {
                "jsonrpc": "2.0", 
                "id": request.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Invalid input or internal processing error"
                }
            }
    
    def _analyze_text(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze text for threats"""
        text = args.get("text", "")
        context = args.get("context", "general")
        
        result = self.guard.analyze_text(text, context)
        
        return {
            "threat_level": result.threat_level.value,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "patterns_detected": result.patterns_detected,
            "execution_commands": result.execution_commands,
            "recommendation": self.guard.get_recommendation(result.threat_level),
            "sanitized_available": result.sanitized_text is not None
        }
    
    def _sanitize_text(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize dangerous text"""
        text = args.get("text", "")
        
        result = self.guard.analyze_text(text)
        
        return {
            "original_text": text,
            "sanitized_text": result.sanitized_text or text,
            "threat_level": result.threat_level.value,
            "patterns_blocked": result.patterns_detected
        }
    
    def _analyze_github_issue(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze GitHub issue for Clinejection attacks"""
        title = args.get("title", "")
        body = args.get("body", "")
        
        analysis = self.guard.analyze_github_issue(title, body)
        
        return {
            "title_threat_level": analysis['title_analysis'].threat_level.value,
            "body_threat_level": analysis['body_analysis'].threat_level.value,
            "overall_threat": analysis['overall_threat'].value,
            "clinejection_risk": analysis['clinejection_risk'],
            "recommendation": analysis['recommendation'],
            "title_risk_score": analysis['title_analysis'].risk_score,
            "body_risk_score": analysis['body_analysis'].risk_score,
            "detected_patterns": {
                "title": analysis['title_analysis'].patterns_detected,
                "body": analysis['body_analysis'].patterns_detected
            }
        }
    
    def _generate_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security analytics report"""
        import datetime
        format_type = args.get("format", "summary")
        
        # Get actual cache statistics
        cache_stats = self.guard.get_cache_stats()
        pattern_info = self.guard.get_pattern_info()
        
        if format_type == "detailed":
            return {
                "report_type": "detailed",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "cache_statistics": cache_stats,
                "pattern_info": pattern_info,
                "protection_status": "Active - Real-time threat detection enabled",
                "version": self.guard.PATTERN_VERSION
            }
        
        return {
            "report_type": "summary", 
            "cache_size": cache_stats["cache_size"],
            "max_cache_size": cache_stats["max_cache_size"],
            "total_patterns": sum(pattern_info.values()),
            "status": "Active"
        }

def main():
    """Run MCP server"""
    server = MCPServer()
    
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
            response = server.handle_request(request)
            print(json.dumps(response))
            sys.stdout.flush()
        except json.JSONDecodeError:
            continue
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": f"Parse error: {str(e)}"
                }
            }
            print(json.dumps(error_response))
            sys.stdout.flush()

if __name__ == "__main__":
    main()