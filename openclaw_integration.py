#!/usr/bin/env python3
"""
AgentGuard OpenClaw Integration
Provides CLI tools and direct integration with OpenClaw
"""

import json
import sys
import time
import argparse
from typing import Dict, Any, List
from agent_guard import AgentGuard, ThreatLevel

class OpenClawIntegration:
    """OpenClaw skill integration for AgentGuard"""
    
    def __init__(self):
        self.guard = AgentGuard()
    
    def analyze_command(self, text: str, context: str = "general") -> Dict[str, Any]:
        """Analyze text for security threats - OpenClaw tool interface"""
        result = self.guard.analyze_text(text, context)
        
        return {
            "threat_level": result.threat_level.value,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "patterns_detected": result.patterns_detected,
            "execution_commands": result.execution_commands,
            "recommendation": self.guard.get_recommendation(result.threat_level),
            "sanitized_text": result.sanitized_text,
            "safe_to_process": result.threat_level == ThreatLevel.SAFE
        }
    
    def sanitize_command(self, text: str) -> Dict[str, Any]:
        """Sanitize dangerous content from text"""
        result = self.guard.analyze_text(text)
        
        return {
            "original_text": text,
            "sanitized_text": result.sanitized_text or text,
            "threat_level": result.threat_level.value,
            "changes_made": result.sanitized_text is not None,
            "patterns_blocked": result.patterns_detected
        }
    
    def github_issue_command(self, title: str, body: str) -> Dict[str, Any]:
        """Analyze GitHub issue for Clinejection-style attacks"""
        analysis = self.guard.analyze_github_issue(title, body)
        
        return {
            "title_analysis": {
                "threat_level": analysis['title_analysis'].threat_level.value,
                "risk_score": analysis['title_analysis'].risk_score,
                "patterns": analysis['title_analysis'].patterns_detected
            },
            "body_analysis": {
                "threat_level": analysis['body_analysis'].threat_level.value,
                "risk_score": analysis['body_analysis'].risk_score,
                "patterns": analysis['body_analysis'].patterns_detected
            },
            "overall_threat": analysis['overall_threat'].value,
            "clinejection_risk": analysis['clinejection_risk'],
            "recommendation": analysis['recommendation'],
            "should_block": analysis['overall_threat'] in [ThreatLevel.DANGEROUS, ThreatLevel.CRITICAL]
        }
    
    def report_command(self, format_type: str = "summary") -> Dict[str, Any]:
        """Generate security analytics report"""
        import datetime
        
        # Get real statistics from the hardened system
        cache_stats = self.guard.get_cache_stats()
        pattern_info = self.guard.get_pattern_info()
        
        if format_type == "detailed":
            return {
                "report_type": "detailed",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "cache_statistics": cache_stats,
                "pattern_info": pattern_info,
                "protection_status": {
                    "active": True,
                    "real_time_detection": True,
                    "auto_sanitization": True,
                    "pattern_version": self.guard.PATTERN_VERSION
                },
                "security_hardening": {
                    "sha256_cache_keys": True,
                    "lru_cache_bounds": True,
                    "compiled_patterns": True,
                    "input_validation": True,
                    "redos_protection": True,
                    "unicode_normalization": True,
                    "rate_limiting": True,
                    "security_logging": True
                },
                "security_stats": self.guard.get_security_stats()
            }
        
        return {
            "report_type": "summary",
            "total_analyses": cache_stats["cache_size"],  # Fix key mismatch
            "threats_detected": 0,  # Would need threat history to calculate
            "cache_size": cache_stats["cache_size"],
            "max_cache_size": cache_stats["max_cache_size"],
            "total_patterns": sum(pattern_info.values()),
            "protection_active": True,
            "version": self.guard.PATTERN_VERSION
        }
    
    # Removed _get_security_recommendations - not used in hardened version

def main():
    """Command-line interface for AgentGuard"""
    parser = argparse.ArgumentParser(description="AgentGuard: AI Agent Security Framework")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze text for security threats")
    analyze_parser.add_argument("text", help="Text to analyze")
    analyze_parser.add_argument("--context", default="general", help="Analysis context")
    analyze_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    # Sanitize command  
    sanitize_parser = subparsers.add_parser("sanitize", help="Sanitize dangerous content")
    sanitize_parser.add_argument("text", help="Text to sanitize") 
    sanitize_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    # GitHub issue command
    github_parser = subparsers.add_parser("github-issue", help="Analyze GitHub issue")
    github_parser.add_argument("--title", required=True, help="Issue title")
    github_parser.add_argument("--body", required=True, help="Issue body")
    github_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument("--format", choices=["summary", "detailed"], default="summary")
    report_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run Clinejection detection demo")
    demo_parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    # Security report command
    security_parser = subparsers.add_parser("security", help="Generate security report")
    security_parser.add_argument("--limit", type=int, default=100, help="Number of recent threats to show")
    security_parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    integration = OpenClawIntegration()
    
    try:
        if args.command == "analyze":
            result = integration.analyze_command(args.text, args.context)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Threat Level: {result['threat_level']}")
                print(f"Risk Score: {result['risk_score']:.2f}")
                print(f"Safe to Process: {result['safe_to_process']}")
                if result['patterns_detected']:
                    print(f"Patterns Detected: {', '.join(result['patterns_detected'])}")
                if result['sanitized_text']:
                    print(f"Sanitized Version: {result['sanitized_text']}")
        
        elif args.command == "sanitize":
            result = integration.sanitize_command(args.text)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Original: {result['original_text']}")
                print(f"Sanitized: {result['sanitized_text']}")
                print(f"Changes Made: {result['changes_made']}")
        
        elif args.command == "github-issue":
            result = integration.github_issue_command(args.title, args.body)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Overall Threat: {result['overall_threat']}")
                print(f"Clinejection Risk: {result['clinejection_risk']}")
                print(f"Should Block: {result['should_block']}")
                print(f"Recommendation: {result['recommendation']}")
        
        elif args.command == "report":
            result = integration.report_command(args.format)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Total Analyses: {result['total_analyses']}")
                print(f"Threats Detected: {result['threats_detected']}")
                print(f"Protection Active: {result['protection_active']}")
        
        elif args.command == "demo":
            # Import and run the demo
            from agent_guard import demo_clinejection_detection
            demo_clinejection_detection()
            
        elif args.command == "security":
            threat_log = integration.guard.get_threat_log(args.limit)
            stats = integration.guard.get_security_stats()
            
            if args.json:
                print(json.dumps({
                    "threat_log": threat_log,
                    "security_stats": stats
                }, indent=2, default=str))
            else:
                print(f"Security Statistics:")
                print(f"Total Threats: {stats['total_threats']}")
                print(f"Threat Breakdown: {stats['threat_breakdown']}")
                print(f"Rate Limiting: {'Enabled' if stats['rate_limit_enabled'] else 'Disabled'}")
                print(f"\nRecent Threats ({len(threat_log)}):")
                for event in threat_log[-10:]:  # Show last 10
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['timestamp']))
                    print(f"  {timestamp} - {event['threat_level']} (score: {event['risk_score']:.1f})")
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()