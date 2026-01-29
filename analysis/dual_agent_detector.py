# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/dual_agent_detector.py
# PANGU Dual-Agent Detection System
# Implementation of Section 3.4: Dual-Agent BAC Detection
# Coordinates Detective and Reviewer for end-to-end vulnerability detection

import sys
import os
import json
from datetime import datetime
from typing import List, Dict, Optional

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, VulnerabilityFinding, AnalysisReport
from analysis.detective_agent import DetectiveAgent
from analysis.reviewer_agent import ReviewerAgent


class DualAgentDetector:
    """
    Dual-Agent Detection System - PANGU Core Detection Engine
    
    Architecture:
    - Detective Agent: Hypothesis generation + Evidence collection
    - Reviewer Agent: Counterfactual verification + Confidence assessment
    
    Workflow:
    1. Load ACDG
    2. Detective performs quick triage on high-risk routes
    3. Detective conducts deep analysis to generate vulnerability hypotheses
    4. Reviewer performs counterfactual verification on each hypothesis
    5. Output final report
    """
    
    def __init__(self, ida_host: str = "localhost", ida_port: int = 18811):
        """Initialize dual-agent system"""
        # IDA Pro connection
        self.ida = IDAProClient(ida_host, ida_port)
        
        # LLM Provider
        self.llm = LLMProvider()
        
        # ACDG
        self.acdg: Optional[ACDG] = None
        
        # Agents
        self.detective: Optional[DetectiveAgent] = None
        self.reviewer: Optional[ReviewerAgent] = None
        
        # Configuration
        self.enable_quick_triage = True
        self.max_routes_per_session = 50
        self.verbose = True
    
    def load_acdg(self, acdg_path: str) -> bool:
        """Load ACDG file"""
        print(f"\n[*] Loading ACDG from: {acdg_path}")
        
        try:
            self.acdg = ACDG.load_json(acdg_path)
            print(f"    Firmware: {self.acdg.firmware_name}")
            print(f"    Routes: {len(self.acdg.routes)}")
            auth_free = self.acdg.get_auth_free_routes()
            print(f"    Auth-Free: {len(auth_free)}")
            return True
        except Exception as e:
            print(f"[!] Failed to load ACDG: {e}")
            return False
    
    def set_acdg(self, acdg: ACDG):
        """Set ACDG object directly"""
        self.acdg = acdg
    
    def check_ida_connection(self) -> bool:
        """Check IDA connection status"""
        print("\n[*] Checking IDA Pro connection...")
        
        try:
            status = self.ida.get_status()
            if status.get("status") == "ok":
                data = status.get("data", {})
                print(f"    Binary: {data.get('binary_name', 'Unknown')}")
                print(f"    Functions: {data.get('function_count', 'Unknown')}")
                return True
            else:
                print(f"    Error: {status.get('error', 'Unknown')}")
                return False
        except Exception as e:
            print(f"    Connection failed: {e}")
            return False
    
    def run(self, output_dir: str = "output") -> AnalysisReport:
        """
        Run dual-agent detection
        
        Complete workflow:
        1. Environment check
        2. Detective investigation
        3. Reviewer verification
        4. Report generation
        """
        start_time = datetime.now()
        
        print("\n" + "=" * 70)
        print(" PANGU Dual-Agent BAC Detection System")
        print(" Detecting Broken Access Control Vulnerabilities")
        print("=" * 70)
        
        # 0. Check prerequisites
        if not self.acdg:
            raise ValueError("ACDG not loaded. Call load_acdg() first.")
        
        if not self.check_ida_connection():
            raise ConnectionError("IDA Pro connection failed")
        
        # 1. Initialize Agents
        print("\n[Phase 1] Initializing Agents...")
        self.detective = DetectiveAgent(self.ida, self.llm, self.acdg)
        self.reviewer = ReviewerAgent(self.ida, self.llm, self.acdg)
        
        # 2. Detective quick triage (optional)
        target_routes = self.acdg.get_auth_free_routes()
        
        if self.enable_quick_triage and len(target_routes) > 10:
            print("\n[Phase 2] Quick Triage...")
            high_risk = self.detective.quick_triage()
            if high_risk:
                target_routes = high_risk[:self.max_routes_per_session]
                print(f"    Focusing on {len(target_routes)} high-risk routes")
        
        # 3. Detective deep investigation
        print("\n[Phase 3] Detective Investigation...")
        self.detective.findings = []  # Reset
        
        for idx, route in enumerate(target_routes):
            if self.verbose:
                print(f"\n[{idx+1}/{len(target_routes)}] Investigating: {route.path}")
            
            finding = self.detective.investigate_route(route)
            if finding:
                self.detective.findings.append(finding)
        
        detective_findings = self.detective.findings
        print(f"\n[*] Detective found {len(detective_findings)} potential vulnerabilities")
        
        # 4. Reviewer verification
        print("\n[Phase 4] Reviewer Verification...")
        verified_findings = self.reviewer.run(detective_findings)
        
        # 5. Generate report
        print("\n[Phase 5] Generating Report...")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        report = AnalysisReport(
            firmware_name=self.acdg.firmware_name,
            analysis_timestamp=start_time.isoformat(),
            total_routes=len(self.acdg.routes),
            auth_free_routes=len(self.acdg.get_auth_free_routes()),
            auth_required_routes=len([r for r in self.acdg.routes if r.auth_state.value == "auth_required"]),
            findings=verified_findings,
            duration_seconds=duration
        )
        
        # Save report
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(output_dir, f"{self.acdg.firmware_name}_vulnerability_report_{timestamp}.json")
        
        self.reviewer.export_report(report_path)
        
        # Print summary
        self._print_summary(report)
        
        return report
    
    def run_detective_only(self) -> List[VulnerabilityFinding]:
        """
        Run Detective only (for debugging or quick scanning)
        """
        if not self.acdg:
            raise ValueError("ACDG not loaded")
        
        print("\n[*] Running Detective Agent only...")
        
        self.detective = DetectiveAgent(self.ida, self.llm, self.acdg)
        return self.detective.run()
    
    def run_interactive(self, route_path: str) -> Optional[VulnerabilityFinding]:
        """
        Interactive single-route analysis
        Used for manual debugging of specific routes
        """
        if not self.acdg:
            raise ValueError("ACDG not loaded")
        
        # Find route
        target_route = None
        for route in self.acdg.routes:
            if route.path == route_path or route.handler == route_path:
                target_route = route
                break
        
        if not target_route:
            print(f"[!] Route not found: {route_path}")
            return None
        
        print(f"\n[*] Interactive analysis: {target_route.path}")
        
        # Initialize Detective
        self.detective = DetectiveAgent(self.ida, self.llm, self.acdg)
        self.detective.verbose = True
        self.detective.max_steps = 10  # Allow more steps
        
        # Investigate
        finding = self.detective.investigate_route(target_route)
        
        if finding:
            print(f"\n[Detective Finding]")
            print(f"  Type: {finding.vuln_type}")
            print(f"  Confidence: {finding.confidence}")
            print(f"  Reasoning: {finding.detective_reasoning}")
            
            # Verification
            print("\n[*] Running Reviewer verification...")
            self.reviewer = ReviewerAgent(self.ida, self.llm, self.acdg)
            self.reviewer.verbose = True
            
            verified = self.reviewer.review_finding(finding)
            if verified:
                print(f"\n[VERIFIED] {verified.vuln_type}")
                print(f"  Severity: {verified.severity}")
                print(f"  CWE: {verified.cwe_id}")
            else:
                print(f"\n[REJECTED] Finding did not pass verification")
            
            return verified
        else:
            print(f"\n[*] No vulnerability found in this route")
            return None
    
    def _print_summary(self, report: AnalysisReport):
        """Print analysis summary"""
        print("\n" + "=" * 70)
        print(" ANALYSIS SUMMARY")
        print("=" * 70)
        
        print(f"\nFirmware: {report.firmware_name}")
        print(f"Duration: {report.duration_seconds:.2f} seconds")
        print(f"\nRoute Analysis:")
        print(f"  Total Routes: {report.total_routes}")
        print(f"  Auth-Free Routes: {report.auth_free_routes}")
        print(f"  Auth-Required Routes: {report.auth_required_routes}")
        
        print(f"\nVulnerability Findings: {len(report.findings)}")
        
        if report.findings:
            # Statistics by severity
            severity_count = {}
            cwe_count = {}
            
            for f in report.findings:
                sev = f.severity or "MEDIUM"
                severity_count[sev] = severity_count.get(sev, 0) + 1
                
                cwe = f.cwe_id or "Unknown"
                cwe_count[cwe] = cwe_count.get(cwe, 0) + 1
            
            print("\n  By Severity:")
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev in severity_count:
                    print(f"    {sev}: {severity_count[sev]}")
            
            print("\n  By CWE:")
            for cwe, count in sorted(cwe_count.items()):
                print(f"    {cwe}: {count}")
            
            print("\n  Detailed Findings:")
            for idx, f in enumerate(report.findings[:10]):  # Show only top 10
                print(f"\n  [{idx+1}] {f.route.path}")
                print(f"      Handler: {f.route.handler}")
                print(f"      Type: {f.vuln_type}")
                print(f"      Severity: {f.severity} | Confidence: {f.confidence}")
                print(f"      CWE: {f.cwe_id}")
        
        print("\n" + "=" * 70)


# ==================== CLI Interface ====================

def main():
    """Command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PANGU Dual-Agent BAC Detector")
    parser.add_argument("acdg", help="Path to ACDG JSON file")
    parser.add_argument("-o", "--output", default="output", help="Output directory")
    parser.add_argument("--host", default="localhost", help="IDA Pro host")
    parser.add_argument("--port", type=int, default=18811, help="IDA Pro port")
    parser.add_argument("--no-triage", action="store_true", help="Disable quick triage")
    parser.add_argument("--max-routes", type=int, default=50, help="Max routes to analyze")
    parser.add_argument("--interactive", "-i", help="Interactive mode for single route")
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = DualAgentDetector(args.host, args.port)
    detector.enable_quick_triage = not args.no_triage
    detector.max_routes_per_session = args.max_routes
    
    # Load ACDG
    if not detector.load_acdg(args.acdg):
        sys.exit(1)
    
    # Run
    if args.interactive:
        detector.run_interactive(args.interactive)
    else:
        detector.run(args.output)


if __name__ == "__main__":
    main()
