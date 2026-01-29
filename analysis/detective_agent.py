# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/detective_agent.py
# PANGU Detective Agent
# Implementation of Section 3.4.1: Detective Agent - Hypothesis Generation & Evidence Seeking
# Vulnerability hypothesis generation and evidence collection based on the ReAct paradigm

import sys
import os
import json
from typing import List, Dict, Optional, Any, TYPE_CHECKING

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, RouteNode, VulnerabilityFinding, AuthState

if TYPE_CHECKING:
    from rag.knowledge_base import KnowledgeBase


class DetectiveAgent:
    """
    Detective Agent - Vulnerability Investigator
    
    Role: Simulates an attacker's perspective to identify potential BAC vulnerabilities
    Operating Mode: ReAct (Reasoning + Acting)
    
    Input:
    - ACDG (Access Control Dependency Graph)
    - List of Auth-Free routes
    - Global authentication mechanism information
    
    Output:
    - List of vulnerability hypotheses with code evidence
    """
    
    # Sensitive operation keywords
    SENSITIVE_SINKS = {
        "rce": ["system", "popen", "exec", "doSystemCmd", "twsystem", "run_cmd"],
        "file_write": ["fwrite", "fputs", "fprintf", "nvram_set", "save_config"],
        "file_read": ["fread", "fgets", "fopen", "nvram_get", "load_config"],
        "config_mod": ["nvram_set", "cfm_set", "setcfg", "CommitCfm"],
        "credential": ["password", "passwd", "wpapsk", "admin", "credential"]
    }
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider, acdg: ACDG, 
                 knowledge_base: Optional['KnowledgeBase'] = None):
        self.ida = ida_client
        self.llm = llm
        self.acdg = acdg
        self.knowledge_base = knowledge_base  # RAG knowledge base
        
        # Tool collection
        self.tools = {
            "decompile": self._tool_decompile,
            "get_callees": self._tool_get_callees,
            "scan_args": self._tool_scan_args,
            "analyze_blocking": self._tool_analyze_blocking,
            "get_xrefs": self._tool_get_xrefs,
            "scan_auth_patterns": self._tool_scan_auth_patterns,
        }
        
        # State
        self.findings: List[VulnerabilityFinding] = []
        self.max_steps = 5
        self.verbose = True
    
    def build_system_prompt(self) -> str:
        """Build system prompt - condensed version"""
        # Only list the first 5 Auth-Free routes to avoid excessive length
        auth_free = self.acdg.get_auth_free_routes()
        routes_info = "\n".join([f"  - {r.path} -> {r.handler}" for r in auth_free[:5]])
        
        # RAG knowledge base context
        rag_context = ""
        if self.knowledge_base and self.knowledge_base.is_loaded:
            rag_context = f"""
## RAG KNOWLEDGE BASE (Device-Specific Intelligence)
{self.knowledge_base.get_full_context()}
"""
        
        return f"""You are a security researcher finding BAC vulnerabilities in Auth-Free handlers.

## Auth-Free Routes (No auth required):
{routes_info}
{rag_context}
## Tools
- `decompile(address)`: Get pseudocode
- `get_callees(address)`: List called functions
- `analyze_blocking(address)`: Check for auth checks

## Sensitive Sinks
- RCE: system(), popen(), doSystemCmd()
- Config: nvram_set(), cfm_set()
- Info Leak: credentials, config data

## Output (JSON)
Action: {{"thought": "...", "action": {{"tool": "name", "args": {{}}}}}}
Finding: {{"thought": "...", "finding": {{"vuln_type": "type", "confidence": "HIGH/MEDIUM/LOW", "evidence": "code", "reasoning": "why"}}}}
"""
    
    def investigate_route(self, route: RouteNode) -> Optional[VulnerabilityFinding]:
        """
        Investigate a single route
        Uses ReAct loop for hypothesis-verification
        """
        if self.verbose:
            print(f"\n[Detective] Investigating: {route.path} -> {route.handler}")
        
        # Get RAG context (if available)
        rag_context = ""
        if self.knowledge_base and self.knowledge_base.is_loaded:
            rag_context = self.knowledge_base.get_context_for_route(route.path, route.handler)
            if rag_context:
                print(f"  [RAG] Found relevant knowledge for this route")
        
        # Initialize conversation history
        history = [
            {"role": "system", "content": self.build_system_prompt()},
            {"role": "user", "content": f"Investigate handler `{route.handler}` for route `{route.path}`. Start by decompiling it.{chr(10) + rag_context if rag_context else ''}"}
        ]
        
        step = 0
        while step < self.max_steps:
            step += 1
            
            # Call LLM
            response = self.llm.chat(history, json_mode=True)
            
            if not response:
                break
            
            # Parse response
            if isinstance(response, str):
                try:
                    response = json.loads(response)
                except:
                    break
            
            thought = response.get("thought", "")
            if self.verbose:
                print(f"  [Step {step}] Thought: {thought[:100]}...")
            
            # Check if there is a finding
            if "finding" in response:
                finding_data = response["finding"]
                finding = VulnerabilityFinding(
                    route=route,
                    vuln_type=finding_data.get("vuln_type", "Unknown"),
                    cwe_id=self._map_to_cwe(finding_data.get("vuln_type", "")),
                    confidence=finding_data.get("confidence", "LOW"),
                    description=finding_data.get("reasoning", ""),
                    evidence=finding_data.get("evidence", ""),
                    detective_reasoning=thought
                )
                if self.verbose:
                    print(f"  [!] Finding: {finding.vuln_type} ({finding.confidence})")
                return finding
            
            # Execute tool
            if "action" in response:
                action = response["action"]
                tool_name = action.get("tool")
                tool_args = action.get("args", {})
                
                if tool_name in self.tools:
                    if self.verbose:
                        print(f"  [Action] {tool_name}({tool_args})")
                    
                    result = self.tools[tool_name](**tool_args)
                    
                    # Add to history
                    history.append({"role": "assistant", "content": json.dumps(response)})
                    history.append({"role": "user", "content": f"Tool Result:\n{result}"})
                else:
                    break
            else:
                break
        
        return None
    
    def run(self) -> List[VulnerabilityFinding]:
        """
        Run Detective Agent
        Iterate through all Auth-Free routes for investigation
        """
        print("\n" + "=" * 60)
        print("PANGU Detective Agent - Starting Investigation")
        print("=" * 60)
        
        auth_free_routes = self.acdg.get_auth_free_routes()
        print(f"[*] {len(auth_free_routes)} Auth-Free routes to investigate")
        
        for idx, route in enumerate(auth_free_routes):
            print(f"\n[{idx+1}/{len(auth_free_routes)}] {route.path}")
            
            finding = self.investigate_route(route)
            if finding:
                self.findings.append(finding)
        
        print(f"\n[*] Investigation complete. Found {len(self.findings)} potential vulnerabilities.")
        return self.findings
    
    def quick_triage(self) -> List[RouteNode]:
        """
        Quick triage: Identify Auth-Free routes containing sensitive operations
        Returns a list of routes most likely to have vulnerabilities
        """
        print("[Detective] Quick triage: Identifying high-risk routes...")
        
        high_risk = []
        auth_free = self.acdg.get_auth_free_routes()
        
        for route in auth_free:
            # Get callees
            res = self.ida.get_callees(route.handler)
            if res.get("status") != "ok":
                continue
            
            callees = res.get("data", [])
            
            # Check if sensitive functions are called
            sensitive_found = []
            for category, sinks in self.SENSITIVE_SINKS.items():
                for sink in sinks:
                    if any(sink.lower() in c.lower() for c in callees):
                        sensitive_found.append((category, sink))
            
            if sensitive_found:
                route.has_sensitive_sink = True
                route.sensitive_sinks = [f"{cat}:{sink}" for cat, sink in sensitive_found]
                high_risk.append(route)
                print(f"  [HIGH RISK] {route.path} -> {route.handler}")
                print(f"              Sensitive: {route.sensitive_sinks}")
        
        print(f"[Detective] Found {len(high_risk)} high-risk routes")
        return high_risk
    
    # ==================== Tool Implementation ====================
    
    def _tool_decompile(self, address: str) -> str:
        """Decompile function"""
        res = self.ida.decompile(address)
        if res.get("status") == "ok":
            data = res.get("data", {})
            if isinstance(data, dict):
                code = data.get("code", "")
                return code[:3000] if len(code) > 3000 else code
            return str(data)[:3000]
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _tool_get_callees(self, address: str) -> str:
        """Get list of called functions"""
        res = self.ida.get_callees(address)
        if res.get("status") == "ok":
            callees = res.get("data", [])
            return json.dumps(callees, indent=2)
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _tool_scan_args(self, address: str) -> str:
        """Scan function arguments"""
        res = self.ida.scan_args(address)
        if res.get("status") == "ok":
            args = res.get("data", [])
            return json.dumps(args[:10], indent=2)  # Limit quantity
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _tool_analyze_blocking(self, address: str) -> str:
        """Analyze blocking behavior"""
        res = self.ida.find_blocking_checks(address, threshold=2.0)
        if res.get("status") == "ok":
            checks = res.get("data", [])
            return json.dumps(checks, indent=2)
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _tool_get_xrefs(self, address: str, direction: str = "from") -> str:
        """Get cross-references"""
        res = self.ida.get_xrefs(address, direction)
        if res.get("status") == "ok":
            xrefs = res.get("data", [])
            return json.dumps(xrefs[:20], indent=2)  # Limit quantity
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _tool_scan_auth_patterns(self, address: str) -> str:
        """Scan authentication patterns"""
        res = self.ida.scan_auth_patterns(address)
        if res.get("status") == "ok":
            patterns = res.get("data", {})
            return json.dumps(patterns, indent=2)
        return f"Error: {res.get('error', 'Unknown')}"
    
    def _map_to_cwe(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE"""
        vuln_lower = vuln_type.lower()
        
        if "rce" in vuln_lower or "command" in vuln_lower:
            return "CWE-78"  # OS Command Injection
        elif "info" in vuln_lower or "disclosure" in vuln_lower or "leak" in vuln_lower:
            return "CWE-200"  # Exposure of Sensitive Information
        elif "config" in vuln_lower or "modification" in vuln_lower:
            return "CWE-284"  # Improper Access Control
        elif "path" in vuln_lower or "traversal" in vuln_lower:
            return "CWE-22"   # Path Traversal
        elif "auth" in vuln_lower or "bypass" in vuln_lower:
            return "CWE-287"  # Improper Authentication
        else:
            return "CWE-284"  # Default to Improper Access Control

    # ==================== Gatekeeper Audit ====================
    
    def build_gatekeeper_prompt(self, gatekeeper_name: str, gatekeeper_code: str) -> str:
        """Build specialized prompt for gatekeeper audit - condensed to avoid token limits"""
        # Limit code length to avoid exceeding model token limits
        max_code_len = 2500
        if len(gatekeeper_code) > max_code_len:
            gatekeeper_code = gatekeeper_code[:max_code_len] + "\n// ... (truncated)"
        
        # RAG knowledge base context
        rag_context = ""
        if self.knowledge_base and self.knowledge_base.is_loaded:
            rag_context = self.knowledge_base.get_context_for_gatekeeper(gatekeeper_name)
            if rag_context:
                rag_context = f"""
## RAG KNOWLEDGE BASE (Device-Specific Intelligence - IMPORTANT!)
{rag_context}
"""
        
        return f"""You are a security expert analyzing a GLOBAL GATEKEEPER function.

## CRITICAL: `{gatekeeper_name}` protects ALL routes. Any bypass affects EVERY protected endpoint!
{rag_context}
## CODE
```c
{gatekeeper_code}
```

## LOOK FOR THESE BYPASS PATTERNS

1. **Path Bypass**: traversal (`/../`), case sensitivity, URL encoding (`%2f`), null byte
2. **Session Flaws**: missing cookie check, predictable tokens, TOCTOU
3. **Logic Errors**: wrong AND/OR, early return, default-allow
4. **String Issues**: strstr vs strcmp, off-by-one

## TOOLS
- `decompile(address)`: Get function code
- `get_callees(address)`: List called functions

## OUTPUT (JSON)
For analysis: {{"thought": "...", "action": {{"tool": "name", "args": {{}}}}}}
For finding: {{"thought": "...", "finding": {{"vuln_type": "Auth Bypass - [type]", "bypass_method": "how", "confidence": "HIGH/MEDIUM/LOW", "evidence": "code"}}}}
If secure: {{"thought": "...", "conclusion": "SECURE", "reasoning": "why"}}
"""

    def investigate_gatekeeper(self, gatekeeper_name: str, gatekeeper_addr: str = None) -> List[VulnerabilityFinding]:
        """
        Audit global gatekeeper for logic vulnerabilities
        This is a critical security audit - gatekeeper vulnerabilities affect all protected routes!
        """
        print(f"\n{'='*60}")
        print(f"[Detective] GATEKEEPER AUDIT: {gatekeeper_name}")
        print(f"{'='*60}")
        print("[!] Critical: Gatekeeper vulnerabilities affect ALL protected routes!")
        
        findings = []
        
        # 1. Decompile gatekeeper function
        print(f"\n[Phase 1] Decompiling gatekeeper...")
        code = self._tool_decompile(gatekeeper_name)
        if "Error" in code:
            print(f"  [FAIL] Cannot decompile: {code}")
            return findings
        print(f"  [OK] Decompiled {len(code)} characters")
        
        # 2. Get functions called by gatekeeper
        print(f"\n[Phase 2] Analyzing callees...")
        callees_json = self._tool_get_callees(gatekeeper_name)
        try:
            callees = json.loads(callees_json)
            print(f"  [OK] Found {len(callees)} callees")
            
            # Mark dangerous functions
            dangerous = ["strstr", "strncmp", "strcmp", "strcasecmp", "websGetVar", "nvram_get"]
            for callee in callees:
                if any(d in callee.lower() for d in dangerous):
                    print(f"  [NOTE] Interesting callee: {callee}")
        except:
            callees = []
        
        # 3. Use LLM for deep analysis
        print(f"\n[Phase 3] LLM deep analysis...")
        
        # Limit code length to avoid exceeding API limits
        code_for_llm = code[:2500] if len(code) > 2500 else code
        print(f"  [INFO] Sending {len(code_for_llm)} chars to LLM (max 2500)")
        
        history = [
            {"role": "system", "content": self.build_gatekeeper_prompt(gatekeeper_name, code_for_llm)},
            {"role": "user", "content": f"Analyze `{gatekeeper_name}` for auth bypass. Check whitelist logic and string comparisons."}
        ]
        
        step = 0
        max_steps = 8  # Gatekeeper audit allows more steps
        
        while step < max_steps:
            step += 1
            
            response = self.llm.chat(history, json_mode=True)
            if not response:
                break
            
            if isinstance(response, str):
                try:
                    response = json.loads(response)
                except:
                    break
            
            # Handle case where LLM returns a list
            if isinstance(response, list):
                if len(response) > 0 and isinstance(response[0], dict):
                    response = response[0]
                else:
                    break
            
            if not isinstance(response, dict):
                break
            
            thought = response.get("thought", "")
            if self.verbose:
                print(f"  [Step {step}] {thought[:100]}...")
            
            # Check if vulnerability found
            if "finding" in response:
                finding_data = response["finding"]
                
                # Create special gatekeeper vulnerability Finding
                # Use a virtual route node to represent the gatekeeper
                from analysis.models import RouteNode, AuthState
                gatekeeper_route = RouteNode(
                    path="[GATEKEEPER]",
                    sub_path="",
                    handler=gatekeeper_name,
                    source_hub="gatekeeper",
                    source_type="security",
                    auth_state=AuthState.AUTH_REQUIRED
                )
                
                finding = VulnerabilityFinding(
                    route=gatekeeper_route,
                    vuln_type=finding_data.get("vuln_type", "Authentication Bypass"),
                    cwe_id="CWE-287",  # Improper Authentication
                    confidence=finding_data.get("confidence", "MEDIUM"),
                    description=f"Bypass: {finding_data.get('bypass_method', '')}\nAffected: {finding_data.get('affected_scope', 'All protected routes')}",
                    evidence=finding_data.get("evidence", ""),
                    detective_reasoning=finding_data.get("reasoning", thought)
                )
                
                print(f"  [!] GATEKEEPER BYPASS FOUND: {finding.vuln_type}")
                print(f"      Bypass Method: {finding_data.get('bypass_method', 'N/A')}")
                print(f"      Affected Scope: {finding_data.get('affected_scope', 'All routes')}")
                findings.append(finding)
            
            # Check if secure
            if "conclusion" in response and response["conclusion"] == "SECURE":
                print(f"  [✓] Gatekeeper appears secure: {response.get('reasoning', '')[:100]}")
                break
            
            # Execute tool
            if "action" in response:
                action = response["action"]
                tool_name = action.get("tool")
                tool_args = action.get("args", {})
                
                if tool_name in self.tools:
                    if self.verbose:
                        print(f"  [Action] {tool_name}({tool_args})")
                    result = self.tools[tool_name](**tool_args)
                    history.append({"role": "assistant", "content": json.dumps(response)})
                    history.append({"role": "user", "content": f"Tool Result:\n{result[:2000]}"})
                else:
                    break
            else:
                break
        
        print(f"\n[Gatekeeper Audit Complete] Found {len(findings)} potential bypass vulnerabilities")
        return findings
    
    def run_comprehensive(self) -> List[VulnerabilityFinding]:
        """
        Run comprehensive vulnerability detection
        Includes: 1) Gatekeeper audit 2) Auth-Free route audit
        """
        all_findings = []
        
        # Phase 1: Audit global gatekeeper
        print("\n" + "=" * 60)
        print("PHASE 1: GATEKEEPER SECURITY AUDIT")
        print("=" * 60)
        
        for mech in self.acdg.global_auth_mechanisms:
            gk_findings = self.investigate_gatekeeper(mech.name, mech.address)
            all_findings.extend(gk_findings)
        
        if not self.acdg.global_auth_mechanisms:
            print("[WARN] No global gatekeeper identified - all routes may be unprotected!")
        
        # Phase 2: Audit Auth-Free routes
        print("\n" + "=" * 60)
        print("PHASE 2: AUTH-FREE ROUTE AUDIT")
        print("=" * 60)
        
        auth_free_routes = self.acdg.get_auth_free_routes()
        print(f"[*] {len(auth_free_routes)} Auth-Free routes to investigate")
        
        for idx, route in enumerate(auth_free_routes):
            print(f"\n[{idx+1}/{len(auth_free_routes)}] {route.path}")
            finding = self.investigate_route(route)
            if finding:
                all_findings.append(finding)
        
        print(f"\n[*] Comprehensive audit complete. Total findings: {len(all_findings)}")
        return all_findings

