# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/reviewer_agent.py
# PANGU Reviewer Agent
# Implementation of Section 3.4.2: Reviewer Agent - Counterfactual Reasoning & Verification
# Validates and evaluates Detective's findings

import sys
import os
import json
from typing import List, Dict, Optional, TYPE_CHECKING
from dataclasses import asdict

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, VulnerabilityFinding

if TYPE_CHECKING:
    from rag.knowledge_base import KnowledgeBase


class ReviewerAgent:
    """
    Reviewer Agent - Vulnerability Assessor
    
    Role: Simulates security auditor perspective to validate Detective's findings
    Methodology: Counterfactual Reasoning
    
    Input:
    - Detective's vulnerability hypothesis list
    - ACDG (for authentication mechanism information)
    
    Output:
    - Validated vulnerability report (with adjusted confidence)
    """
    
    # Counterfactual checkpoints
    COUNTERFACTUAL_CHECKS = [
        "auth_bypass",        # Did it really bypass authentication?
        "reachability",       # Is the sensitive operation reachable?
        "user_controllable",  # Are parameters user-controllable?
        "exploitability",     # Can a valid exploit be constructed?
        "alternative_path",   # Are there other authentication paths?
    ]
    
    def __init__(self, ida_client: IDAProClient, llm: LLMProvider, acdg: ACDG,
                 knowledge_base: Optional['KnowledgeBase'] = None):
        self.ida = ida_client
        self.llm = llm
        self.acdg = acdg
        self.knowledge_base = knowledge_base  # RAG knowledge base
        
        self.verified_findings: List[VulnerabilityFinding] = []
        self.rejected_count = 0
        self.verbose = True
    
    def build_review_prompt(self, finding: VulnerabilityFinding) -> str:
        """Build review prompt"""
        
        # Format global authentication information
        auth_mechanisms = ""
        for mech in self.acdg.global_auth_mechanisms:
            auth_mechanisms += f"  - {mech.name}: Type={mech.mechanism_type}, Confidence={mech.confidence:.2f}\n"
        if not auth_mechanisms:
            auth_mechanisms = "  (None identified)\n"
        
        # RAG knowledge base context
        rag_context = ""
        if self.knowledge_base and self.knowledge_base.is_loaded:
            # Search for related known vulnerabilities
            related_vulns = self.knowledge_base.search_vulnerabilities(
                route=finding.route.path,
                handler=finding.route.handler,
                vuln_type=finding.vuln_type
            )
            if related_vulns:
                rag_context = "\n## RAG KNOWLEDGE BASE - RELATED KNOWN VULNERABILITIES\n"
                for vuln in related_vulns:
                    rag_context += f"- **{vuln.cve_id}** ({vuln.vuln_type})\n"
                    rag_context += f"  Description: {vuln.description}\n"
                    rag_context += f"  Exploit: {vuln.exploit_method}\n"
                rag_context += "\nNote: Use this information to validate the finding. If similar CVEs exist, the finding is more likely valid.\n"
        
        return f"""You are "Reviewer", a skeptical security auditor.
Your task: Critically evaluate a potential vulnerability finding using counterfactual reasoning.

## DETECTIVE'S FINDING

**Handler**: {finding.route.handler}
**Route**: {finding.route.path}
**Claimed Vulnerability**: {finding.vuln_type}
**Confidence**: {finding.confidence}
**Detective's Reasoning**: {finding.detective_reasoning}

**Code Evidence**:
```c
{finding.evidence[:2000]}
```

## KNOWN AUTHENTICATION MECHANISMS

{auth_mechanisms}
{rag_context}
## YOUR COUNTERFACTUAL ANALYSIS

For each question, reason through the alternative scenarios:

1. **Authentication Bypass**: 
   - Could there be authentication checks in the caller functions?
   - Is this handler actually called only after authentication in practice?
   
2. **Reachability**:
   - Can an unauthenticated user actually reach the sensitive operation?
   - Are there conditional checks that would block the exploit path?
   
3. **User Controllability**:
   - Are the parameters to sensitive functions truly user-controllable?
   - Could they be sanitized or validated elsewhere?
   
4. **Exploitability**:
   - Can a working exploit be constructed?
   - Are there practical constraints (buffer sizes, character filters)?
   
5. **Alternative Paths**:
   - Might there be alternative authenticated routes to the same functionality?
   - Is this truly an unintended access path?

## RESPONSE FORMAT

{{
    "analysis": {{
        "auth_bypass": {{
            "verified": true/false,
            "reasoning": "..."
        }},
        "reachability": {{
            "verified": true/false,
            "reasoning": "..."
        }},
        "user_controllable": {{
            "verified": true/false,
            "reasoning": "..."
        }},
        "exploitability": {{
            "verified": true/false,
            "reasoning": "..."
        }},
        "alternative_path": {{
            "found": true/false,
            "description": "..."
        }}
    }},
    "verdict": {{
        "is_valid": true/false,
        "adjusted_confidence": "HIGH/MEDIUM/LOW",
        "cwe_id": "CWE-XXX",
        "final_reasoning": "Summary of why this is/isn't a valid vulnerability",
        "severity": "CRITICAL/HIGH/MEDIUM/LOW",
        "attack_vector": "Description of how to exploit (if valid)"
    }}
}}
"""
    
    def review_finding(self, finding: VulnerabilityFinding) -> Optional[VulnerabilityFinding]:
        """
        Review a single finding
        Use counterfactual reasoning to validate vulnerability effectiveness
        """
        if self.verbose:
            print(f"\n[Reviewer] Reviewing: {finding.route.handler} - {finding.vuln_type}")
        
        # Get more context (if needed)
        additional_context = self._gather_additional_context(finding)
        
        # Build review request
        prompt = self.build_review_prompt(finding)
        if additional_context:
            prompt += f"\n\n## ADDITIONAL CONTEXT\n{additional_context}"
        
        # Call LLM for review
        response = self.llm.chat([
            {"role": "system", "content": "You are a skeptical security auditor performing counterfactual analysis."},
            {"role": "user", "content": prompt}
        ], json_mode=True)
        
        if not response:
            print("  [!] LLM response empty, keeping original finding")
            return finding
        
        # Parse response
        if isinstance(response, str):
            try:
                response = json.loads(response)
            except:
                print("  [!] Failed to parse response, keeping original finding")
                return finding
        
        verdict = response.get("verdict", {})
        analysis = response.get("analysis", {})
        
        if self.verbose:
            print(f"  [Analysis] Auth Bypass: {analysis.get('auth_bypass', {}).get('verified', 'N/A')}")
            print(f"  [Analysis] Reachability: {analysis.get('reachability', {}).get('verified', 'N/A')}")
            print(f"  [Analysis] User Control: {analysis.get('user_controllable', {}).get('verified', 'N/A')}")
        
        # Determine if valid
        is_valid = verdict.get("is_valid", False)
        
        if is_valid:
            # Update finding
            finding.confidence = verdict.get("adjusted_confidence", finding.confidence)
            finding.cwe_id = verdict.get("cwe_id", finding.cwe_id)
            finding.reviewer_verdict = verdict.get("final_reasoning", "")
            finding.severity = verdict.get("severity", "MEDIUM")
            finding.attack_vector = verdict.get("attack_vector", "")
            finding.counterfactual_analysis = analysis
            
            if self.verbose:
                print(f"  [VERIFIED] {finding.vuln_type} - Confidence: {finding.confidence}")
            return finding
        else:
            if self.verbose:
                reason = verdict.get("final_reasoning", "Unknown reason")
                print(f"  [REJECTED] Reason: {reason[:100]}")
            self.rejected_count += 1
            return None
    
    def _gather_additional_context(self, finding: VulnerabilityFinding) -> str:
        """
        Collect additional context information for review
        """
        context_parts = []
        
        # 1. Get caller information
        handler_addr = finding.route.handler
        xrefs_res = self.ida.get_xrefs(handler_addr, "to")
        if xrefs_res.get("status") == "ok":
            callers = xrefs_res.get("data", [])
            if callers:
                context_parts.append(f"Callers of {handler_addr}: {callers[:5]}")
        
        # 2. Check if there is parameter validation
        args_res = self.ida.scan_args(handler_addr)
        if args_res.get("status") == "ok":
            args = args_res.get("data", [])
            context_parts.append(f"Function arguments: {json.dumps(args[:5])}")
        
        return "\n".join(context_parts)
    
    def run(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """
        Run Reviewer Agent
        Review all Detective's findings
        """
        print("\n" + "=" * 60)
        print("PANGU Reviewer Agent - Starting Verification")
        print("=" * 60)
        print(f"[*] {len(findings)} findings to review")
        
        self.verified_findings = []
        self.rejected_count = 0
        
        for idx, finding in enumerate(findings):
            print(f"\n[{idx+1}/{len(findings)}] {finding.route.path} - {finding.vuln_type}")
            
            verified = self.review_finding(finding)
            if verified:
                self.verified_findings.append(verified)
        
        print(f"\n[*] Verification complete.")
        print(f"    Verified: {len(self.verified_findings)}")
        print(f"    Rejected: {self.rejected_count}")
        
        return self.verified_findings
    
    def generate_cwe_summary(self) -> Dict[str, List[VulnerabilityFinding]]:
        """
        Generate vulnerability summary grouped by CWE
        """
        cwe_groups: Dict[str, List[VulnerabilityFinding]] = {}
        
        for finding in self.verified_findings:
            cwe = finding.cwe_id or "CWE-Unknown"
            if cwe not in cwe_groups:
                cwe_groups[cwe] = []
            cwe_groups[cwe].append(finding)
        
        return cwe_groups
    
    def export_report(self, output_path: str):
        """
        Export review report
        """
        report = {
            "summary": {
                "total_findings": len(self.verified_findings),
                "by_severity": {},
                "by_cwe": {}
            },
            "findings": []
        }
        
        # Statistics
        for finding in self.verified_findings:
            # Count by severity
            sev = finding.severity or "MEDIUM"
            report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1
            
            # Count by CWE
            cwe = finding.cwe_id or "Unknown"
            report["summary"]["by_cwe"][cwe] = report["summary"]["by_cwe"].get(cwe, 0) + 1
            
            # Add details
            report["findings"].append({
                "route": finding.route.path,
                "handler": finding.route.handler,
                "vuln_type": finding.vuln_type,
                "cwe_id": finding.cwe_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "description": finding.description,
                "evidence": finding.evidence[:1000] if finding.evidence else "",
                "attack_vector": finding.attack_vector,
                "reviewer_verdict": finding.reviewer_verdict
            })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Report exported to: {output_path}")
        return report
