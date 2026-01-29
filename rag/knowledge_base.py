# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# rag/knowledge_base.py
"""
PANGU RAG Knowledge Base Module
External knowledge base loading and query module for enhancing Phase 3 vulnerability detection
"""

import os
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class KnownVulnerability:
    """Known Vulnerability Information"""
    cve_id: str
    vuln_type: str
    affected_route: str
    affected_handler: str
    description: str
    exploit_method: str
    references: List[str] = field(default_factory=list)


@dataclass
class DeviceInfo:
    """Device Information"""
    vendor: str
    model: str
    firmware_version: str
    architecture: str
    web_server: str


@dataclass
class SecurityPatterns:
    """Security Pattern Information"""
    auth_mechanism: str
    known_auth_bypass: List[str]
    sensitive_endpoints: List[str]
    default_credentials: List[str]


class KnowledgeBase:
    """
    RAG Knowledge Base
    
    Supports two formats:
    1. Structured JSON format ({firmware}_knowledge.json)
    2. Plain text format ({firmware}_knowledge.txt or .md)
    
    Plain text format is simpler, just paste vulnerability descriptions
    """
    
    def __init__(self, firmware_name: str, rag_dir: str = "rag"):
        self.firmware_name = firmware_name
        self.rag_dir = rag_dir
        
        # Knowledge base data
        self.device_info: Optional[DeviceInfo] = None
        self.known_vulnerabilities: List[KnownVulnerability] = []
        self.security_patterns: Optional[SecurityPatterns] = None
        self.additional_context: str = ""
        
        # Plain text content (new)
        self.raw_text_content: str = ""
        self.is_text_format: bool = False
        
        # Raw data
        self._raw_data: Dict = {}
        
        # Load status
        self.is_loaded = False
    
    def load(self) -> bool:
        """
        Load knowledge base file
        Prioritize plain text format, then JSON format
        
        Returns:
            bool: Whether loading succeeded
        """
        # Try to load plain text format (preferred)
        for ext in ['.txt', '.md']:
            text_file = os.path.join(self.rag_dir, f"{self.firmware_name}_knowledge{ext}")
            if os.path.exists(text_file):
                return self._load_text_format(text_file)
        
        # Try to load JSON format
        json_file = os.path.join(self.rag_dir, f"{self.firmware_name}_knowledge.json")
        if os.path.exists(json_file):
            return self._load_json_format(json_file)
        
        print(f"[RAG] Knowledge base not found for: {self.firmware_name}")
        print(f"      Expected: {self.rag_dir}/{self.firmware_name}_knowledge.txt/md/json")
        return False
    
    def _load_text_format(self, filepath: str) -> bool:
        """Load plain text format knowledge base."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.raw_text_content = f.read().strip()
            
            self.is_text_format = True
            self.is_loaded = True
            
            # Create simple device info
            self.device_info = DeviceInfo(
                vendor="Unknown",
                model=self.firmware_name,
                firmware_version="Unknown",
                architecture="Unknown",
                web_server="Unknown"
            )
            
            print(f"[RAG] Text knowledge base loaded: {filepath}")
            print(f"      Content length: {len(self.raw_text_content)} chars")
            
            return True
            
        except Exception as e:
            print(f"[RAG] Failed to load text knowledge base: {e}")
            return False
    
    def _load_json_format(self, filepath: str) -> bool:
        """Load JSON format knowledge base."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self._raw_data = json.load(f)
            
            # Parse device information
            if "device_info" in self._raw_data:
                di = self._raw_data["device_info"]
                self.device_info = DeviceInfo(
                    vendor=di.get("vendor", "Unknown"),
                    model=di.get("model", "Unknown"),
                    firmware_version=di.get("firmware_version", "Unknown"),
                    architecture=di.get("architecture", "Unknown"),
                    web_server=di.get("web_server", "Unknown")
                )
            
            # Parse known vulnerabilities
            if "known_vulnerabilities" in self._raw_data:
                for vuln in self._raw_data["known_vulnerabilities"]:
                    self.known_vulnerabilities.append(KnownVulnerability(
                        cve_id=vuln.get("cve_id", ""),
                        vuln_type=vuln.get("vuln_type", ""),
                        affected_route=vuln.get("affected_route", ""),
                        affected_handler=vuln.get("affected_handler", ""),
                        description=vuln.get("description", ""),
                        exploit_method=vuln.get("exploit_method", ""),
                        references=vuln.get("references", [])
                    ))
            
            # Parse security patterns
            if "security_patterns" in self._raw_data:
                sp = self._raw_data["security_patterns"]
                self.security_patterns = SecurityPatterns(
                    auth_mechanism=sp.get("auth_mechanism", ""),
                    known_auth_bypass=sp.get("known_auth_bypass", []),
                    sensitive_endpoints=sp.get("sensitive_endpoints", []),
                    default_credentials=sp.get("default_credentials", [])
                )
            
            # Additional context
            self.additional_context = self._raw_data.get("additional_context", "")
            
            self.is_loaded = True
            self.is_text_format = False
            
            print(f"[RAG] JSON knowledge base loaded: {filepath}")
            print(f"      Device: {self.device_info.vendor} {self.device_info.model}" if self.device_info else "")
            print(f"      Known Vulnerabilities: {len(self.known_vulnerabilities)}")
            
            return True
            
        except Exception as e:
            print(f"[RAG] Failed to load JSON knowledge base: {e}")
            return False
    
    def get_context_for_route(self, route_path: str, handler_name: str = "") -> str:
        """Get knowledge base context for a specific route."""
        if not self.is_loaded:
            return ""
        
        # Plain text mode: return full content (LLM will understand it)
        if self.is_text_format:
            return f"""## RAG KNOWLEDGE BASE (Device Background & Known Vulnerabilities)
{self.raw_text_content}

Note: Check if any known vulnerabilities above relate to route `{route_path}` or handler `{handler_name}`.
"""
        
        # JSON mode: precise matching
        context_parts = []
        
        related_vulns = []
        for vuln in self.known_vulnerabilities:
            if vuln.affected_route and (
                vuln.affected_route.lower() in route_path.lower() or
                route_path.lower() in vuln.affected_route.lower()
            ):
                related_vulns.append(vuln)
            elif vuln.affected_handler and handler_name and (
                vuln.affected_handler.lower() in handler_name.lower() or
                handler_name.lower() in vuln.affected_handler.lower()
            ):
                related_vulns.append(vuln)
        
        if related_vulns:
            context_parts.append("## KNOWN VULNERABILITIES (from RAG Knowledge Base)")
            for vuln in related_vulns:
                context_parts.append(f"- **{vuln.cve_id}** ({vuln.vuln_type})")
                context_parts.append(f"  Description: {vuln.description}")
                context_parts.append(f"  Exploit: {vuln.exploit_method}")
        
        if self.security_patterns:
            for endpoint in self.security_patterns.sensitive_endpoints:
                if route_path.lower() in endpoint.lower():
                    context_parts.append(f"\n## SENSITIVE ENDPOINT WARNING")
                    context_parts.append(f"This route `{route_path}` matches known sensitive endpoint: {endpoint}")
                    break
        
        return "\n".join(context_parts) if context_parts else ""
    
    def get_context_for_gatekeeper(self, gatekeeper_name: str) -> str:
        """Get knowledge base context for a gatekeeper function."""
        if not self.is_loaded:
            return ""
        
        # Plain text mode: return full content
        if self.is_text_format:
            return f"""## RAG KNOWLEDGE BASE (Device Background & Known Vulnerabilities)
{self.raw_text_content}

Note: Use this information to help analyze gatekeeper `{gatekeeper_name}`. 
Look for any mentioned auth bypass patterns or security issues.
"""
        
        # JSON mode
        context_parts = []
        
        if self.device_info:
            context_parts.append("## DEVICE INFORMATION (from RAG Knowledge Base)")
            context_parts.append(f"- Vendor: {self.device_info.vendor}")
            context_parts.append(f"- Model: {self.device_info.model}")
            context_parts.append(f"- Web Server: {self.device_info.web_server}")
        
        if self.security_patterns:
            context_parts.append("\n## KNOWN AUTH MECHANISM")
            context_parts.append(f"- {self.security_patterns.auth_mechanism}")
            
            if self.security_patterns.known_auth_bypass:
                context_parts.append("\n## KNOWN AUTH BYPASS PATTERNS (IMPORTANT!)")
                for bypass in self.security_patterns.known_auth_bypass:
                    context_parts.append(f"- {bypass}")
        
        related_vulns = [v for v in self.known_vulnerabilities 
                        if gatekeeper_name.lower() in v.affected_handler.lower() or
                        "auth" in v.vuln_type.lower() or
                        "bypass" in v.vuln_type.lower()]
        
        if related_vulns:
            context_parts.append("\n## RELATED KNOWN VULNERABILITIES")
            for vuln in related_vulns:
                context_parts.append(f"- **{vuln.cve_id}**: {vuln.description}")
                context_parts.append(f"  Exploit: {vuln.exploit_method}")
        
        if self.additional_context:
            context_parts.append(f"\n## ADDITIONAL CONTEXT")
            context_parts.append(self.additional_context)
        
        return "\n".join(context_parts) if context_parts else ""
    
    def get_full_context(self) -> str:
        """Get full knowledge base context."""
        if not self.is_loaded:
            return ""
        
        # Plain text mode
        if self.is_text_format:
            return f"""## RAG KNOWLEDGE BASE
{self.raw_text_content}
"""
        
        # JSON mode
        parts = []
        
        if self.device_info:
            parts.append("## DEVICE INFORMATION")
            parts.append(f"- Vendor: {self.device_info.vendor}")
            parts.append(f"- Model: {self.device_info.model}")
            parts.append(f"- Firmware: {self.device_info.firmware_version}")
            parts.append(f"- Architecture: {self.device_info.architecture}")
            parts.append(f"- Web Server: {self.device_info.web_server}")
        
        if self.known_vulnerabilities:
            parts.append("\n## KNOWN VULNERABILITIES")
            for vuln in self.known_vulnerabilities:
                parts.append(f"- [{vuln.cve_id}] {vuln.vuln_type}")
                parts.append(f"  Route: {vuln.affected_route}")
                parts.append(f"  Description: {vuln.description[:200]}...")
        
        if self.security_patterns:
            parts.append("\n## SECURITY PATTERNS")
            parts.append(f"Auth Mechanism: {self.security_patterns.auth_mechanism}")
            
            if self.security_patterns.known_auth_bypass:
                parts.append("\nKnown Auth Bypass:")
                for bypass in self.security_patterns.known_auth_bypass:
                    parts.append(f"  - {bypass}")
            
            if self.security_patterns.sensitive_endpoints:
                parts.append("\nSensitive Endpoints:")
                for ep in self.security_patterns.sensitive_endpoints[:10]:
                    parts.append(f"  - {ep}")
        
        if self.additional_context:
            parts.append(f"\n## ADDITIONAL CONTEXT")
            parts.append(self.additional_context)
        
        return "\n".join(parts)
    
    def search_vulnerabilities(self, 
                               route: str = None, 
                               handler: str = None,
                               vuln_type: str = None) -> List[KnownVulnerability]:
        """Search for related known vulnerabilities (only effective for JSON format)."""
        if not self.is_loaded or self.is_text_format:
            return []
        
        results = []
        
        for vuln in self.known_vulnerabilities:
            match = False
            
            if route and vuln.affected_route:
                if route.lower() in vuln.affected_route.lower() or \
                   vuln.affected_route.lower() in route.lower():
                    match = True
            
            if handler and vuln.affected_handler:
                if handler.lower() in vuln.affected_handler.lower() or \
                   vuln.affected_handler.lower() in handler.lower():
                    match = True
            
            if vuln_type and vuln.vuln_type:
                if vuln_type.lower() in vuln.vuln_type.lower():
                    match = True
            
            if match:
                results.append(vuln)
        
        return results
    
    def get_sensitive_sinks(self) -> List[str]:
        """Extract sensitive sink functions from knowledge base."""
        sinks = []
        
        if self.device_info:
            ws = self.device_info.web_server.lower()
            if "goahead" in ws:
                sinks.extend(["websGetVar", "websRedirect", "websWrite"])
        
        for vuln in self.known_vulnerabilities:
            desc = vuln.description.lower() + " " + vuln.exploit_method.lower()
            if "command" in desc or "rce" in desc.lower():
                if "dosystemcmd" in desc:
                    sinks.append("doSystemCmd")
                if "system" in desc:
                    sinks.append("system")
                if "popen" in desc:
                    sinks.append("popen")
        
        return list(set(sinks))

