# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/pangu_pipeline.py
# PANGU Complete Analysis Pipeline
# Chains the four stages described in the paper: Preprocessing -> Route Extraction -> Logic Decoupling -> Dual-Agent Detection

import sys
import os
import argparse
from datetime import datetime
from typing import Optional

sys.path.append(os.getcwd())

from core.bridge.ida_client import IDAProClient
from core.llm import LLMProvider
from analysis.models import ACDG, RouteNode, AuthMechanism, AuthState
from analysis.logic_decoupler import LogicDecoupler
from analysis.dual_agent_detector import DualAgentDetector
from analysis.route_extractor import RouteExtractor
from analysis.fastcgi_extractor import FastCGIExtractor, ArchitectureDetector, create_extractor_for_architecture


class PANGUPipeline:
    """
    PANGU Complete Analysis Pipeline
    
    Four-stage architecture (Section 3 of paper):
    1. Preprocessing: Firmware unpacking + Binary loading
    2. Route Extraction: Route-Handler mapping extraction
    3. Logic Decoupling: Auth-Required vs Auth-Free classification
    4. Dual-Agent Detection: Vulnerability detection and verification
    
    Supported Web Server Architectures:
    - GoAhead: Traditional websFormDefine/websUrlHandlerDefine registration
    - FastCGI: strncmp dispatch pattern (e.g., H3C NX15)
    - Auto-detection or manual specification
    """
    
    def __init__(self, ida_host: str = "localhost", ida_port: int = 18811):
        """Initialize pipeline"""
        self.ida = IDAProClient(ida_host, ida_port)
        self.llm = LLMProvider()
        
        # Stage outputs
        self.raw_routes = []              # Stage 2 output
        self.acdg: Optional[ACDG] = None  # Stage 3 output
        self.findings = []                # Stage 4 output
        
        # Architecture detection
        self.detected_architecture: str = "auto"  # auto, GoAhead, FastCGI, etc.
        
        # Configuration
        self.output_dir = "output"
        self.firmware_name = "Unknown"
        self.verbose = True
    
    def check_connection(self) -> bool:
        """Check IDA connection"""
        print("\n[Phase 0] Checking IDA Pro connection...")
        try:
            status = self.ida.get_status()
            if status.get("status") == "ok":
                data = status.get("data", {})
                self.firmware_name = data.get("binary_name", "Unknown")
                print(f"    Binary: {self.firmware_name}")
                print(f"    Functions: {data.get('function_count', 'N/A')}")
                return True
            return False
        except Exception as e:
            print(f"    Error: {e}")
            return False
    
    def phase1_preprocessing(self):
        """
        Phase 1: Preprocessing
        - Firmware unpacking (Binwalk)
        - Binary identification and loading (IDA Pro)
        - Basic information collection
        
        Note: Current version assumes user has manually completed this step
        """
        print("\n" + "=" * 60)
        print("[Phase 1] Preprocessing")
        print("=" * 60)
        print("  NOTE: Assuming binary is already loaded in IDA Pro")
        print(f"  Binary: {self.firmware_name}")
    
    def phase2_route_extraction(self, routes_json: Optional[str] = None, use_enhanced_scan: bool = False, 
                                   architecture: str = "auto"):
        """
        Phase 2: Route Extraction
        - Identify HTTP entry points
        - Trace route registration logic
        - Build Route -> Handler mapping
        
        Args:
            routes_json: Optional, path to existing routes JSON file
            use_enhanced_scan: Whether to use enhanced scanning (EnhancedTableScanner)
            architecture: Architecture type ("auto", "GoAhead", "FastCGI", etc.)
        """
        print("\n" + "=" * 60)
        print("[Phase 2] Route Extraction")
        print("=" * 60)
        
        if routes_json and os.path.exists(routes_json):
            # Load existing routes
            print(f"  Loading existing routes from: {routes_json}")
            
            extractor = RouteExtractor(self.ida, self.llm)
            extractor.verbose = self.verbose
            self.raw_routes = extractor.load_routes_from_file(routes_json)
            
            # Convert to dict format for compatibility with subsequent processing
            self.raw_routes = [
                {
                    "path": r.path,
                    "sub_path": r.sub_path,
                    "handler": r.handler,
                    "source_hub": r.source_hub,
                    "source_type": r.source_type,
                    "root": r.root
                }
                for r in extractor.routes
            ]
            
            print(f"  Loaded {len(self.raw_routes)} routes")
        else:
            # Architecture detection
            actual_arch = architecture
            if architecture == "auto":
                print("  [*] Auto-detecting architecture...")
                detector = ArchitectureDetector(self.ida)
                actual_arch, confidence = detector.detect()
                self.detected_architecture = actual_arch
                print(f"  [+] Detected architecture: {actual_arch} (confidence: {confidence:.1%})")
            else:
                actual_arch = architecture
                self.detected_architecture = architecture
                print(f"  [*] Using specified architecture: {actual_arch}")
            
            # Select extractor based on architecture
            if actual_arch in ["FastCGI", "Lighttpd"]:
                # Use FastCGI extractor
                print("  [*] Using FastCGI route extractor...")
                extractor = FastCGIExtractor(self.ida, self.llm)
                extractor.verbose = self.verbose
                extractor.output_dir = self.output_dir
                
                routes = extractor.run(use_llm=True)
                
                # Save extraction results
                saved_path = extractor.save_routes(self.firmware_name)
                
                # Convert format
                self.raw_routes = [
                    {
                        "path": r.path,
                        "sub_path": r.sub_path,
                        "handler": r.handler,
                        "source_hub": r.source_hub,
                        "source_type": r.source_type,
                        "root": r.root,
                        "auth_state": r.auth_state.value,
                        "protection_type": r.protection_type.value,
                        "protection_detail": r.protection_detail
                    }
                    for r in routes
                ]
                
                print(f"  Extracted {len(self.raw_routes)} routes (FastCGI)")
                print(f"  Saved to: {saved_path}")
            else:
                # Use original RouteExtractor (GoAhead, etc.)
                scan_mode = "enhanced" if use_enhanced_scan else "standard"
                print(f"  Running full route extraction (mode: {scan_mode})...")
                
                extractor = RouteExtractor(self.ida, self.llm)
                extractor.verbose = self.verbose
                extractor.output_dir = self.output_dir
                extractor.log_dir = "logs"
                
                # Select scan mode
                if use_enhanced_scan:
                    print("  [*] Using Enhanced Table Scanner...")
                    routes = extractor.run_enhanced()
                else:
                    routes = extractor.run()
                
                # Save extraction results
                saved_path = extractor.save_routes()
                
                # Convert format
                self.raw_routes = [
                    {
                        "path": r.path,
                        "sub_path": r.sub_path,
                        "handler": r.handler,
                        "source_hub": r.source_hub,
                        "source_type": r.source_type,
                        "root": r.root
                    }
                    for r in routes
                ]
                
                print(f"  Extracted {len(self.raw_routes)} routes (GoAhead/Standard)")
                print(f"  Saved to: {saved_path}")
    
    def phase3_logic_decoupling(self):
        """
        Phase 3: Logic Decoupling
        - Global authentication mechanism identification (dominator tree analysis)
        - Local authentication constraint identification (TIS computation)
        - Build ACDG (Access Control Dependency Graph)
        """
        print("\n" + "=" * 60)
        print("[Phase 3] Logic Decoupling")
        print("=" * 60)
        
        if not self.raw_routes:
            print("  ERROR: No routes available. Run Phase 2 first.")
            return
        
        # Initialize Logic Decoupler
        decoupler = LogicDecoupler(self.ida, self.llm)
        decoupler.verbose = self.verbose
        
        # Convert raw routes to RouteNode
        route_nodes = []
        for r in self.raw_routes:
            node = RouteNode(
                path=r.get("path", ""),
                sub_path=r.get("sub_path", ""),
                handler=r.get("handler", ""),
                source_hub=r.get("source_hub", ""),
                source_type=r.get("source_type", "unknown"),
                root=r.get("root", "/")
            )
            route_nodes.append(node)
        
        print(f"  Input: {len(route_nodes)} routes")
        
        # Run logic decoupling
        self.acdg = decoupler.run(route_nodes, self.firmware_name)
        
        # Save ACDG
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        acdg_path = os.path.join(self.output_dir, f"{self.firmware_name}_acdg_{timestamp}.json")
        self.acdg.save_json(acdg_path)
        print(f"  ACDG saved to: {acdg_path}")
    
    def phase4_dual_agent_detection(self, acdg_path: Optional[str] = None):
        """
        Phase 4: Dual-Agent Vulnerability Detection
        - Detective: Hypothesis generation + Evidence collection
        - Reviewer: Counterfactual verification
        - Output vulnerability report
        
        Args:
            acdg_path: Optional, path to existing ACDG file
        """
        print("\n" + "=" * 60)
        print("[Phase 4] Dual-Agent Detection")
        print("=" * 60)
        
        # Load or use existing ACDG
        if acdg_path and os.path.exists(acdg_path):
            print(f"  Loading ACDG from: {acdg_path}")
            self.acdg = ACDG.load_json(acdg_path)
        
        if not self.acdg:
            print("  ERROR: No ACDG available. Run Phase 3 first.")
            return
        
        # Initialize dual-agent detector
        detector = DualAgentDetector()
        detector.set_acdg(self.acdg)
        detector.verbose = self.verbose
        
        # Run detection
        report = detector.run(self.output_dir)
        self.findings = report.findings
        
        print(f"\n  Detection complete: {len(self.findings)} vulnerabilities found")
    
    def run_full_pipeline(self, routes_json: Optional[str] = None, 
                          acdg_path: Optional[str] = None,
                          skip_phase: int = 0):
        """
        Run full pipeline
        
        Args:
            routes_json: Existing routes file (skip Phase 2 extraction)
            acdg_path: Existing ACDG file (skip Phase 3 decoupling)
            skip_phase: Skip first N phases
        """
        start_time = datetime.now()
        
        print("\n" + "=" * 70)
        print(" PANGU - IoT Firmware BAC Vulnerability Detector")
        print(" Full Pipeline Execution")
        print("=" * 70)
        
        # Check connection
        if not self.check_connection():
            print("\n[FATAL] Cannot connect to IDA Pro. Aborting.")
            return
        
        # Phase 1: Preprocessing
        if skip_phase < 1:
            self.phase1_preprocessing()
        
        # Phase 2: Route extraction
        if skip_phase < 2:
            self.phase2_route_extraction(routes_json)
        
        # Phase 3: Logic decoupling
        if skip_phase < 3 and not acdg_path:
            self.phase3_logic_decoupling()
        
        # Phase 4: Dual-agent detection
        if skip_phase < 4:
            self.phase4_dual_agent_detection(acdg_path)
        
        # Complete
        duration = (datetime.now() - start_time).total_seconds()
        
        print("\n" + "=" * 70)
        print(" Pipeline Complete")
        print("=" * 70)
        print(f"  Duration: {duration:.2f} seconds")
        print(f"  Routes analyzed: {len(self.raw_routes) if self.raw_routes else 'N/A'}")
        print(f"  Auth-Free routes: {self.acdg.auth_free_count if self.acdg else 'N/A'}")
        print(f"  Vulnerabilities: {len(self.findings)}")
        print("=" * 70)


def main():
    """Command line entry point"""
    parser = argparse.ArgumentParser(
        description="PANGU - IoT Firmware BAC Vulnerability Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline with existing routes
  python pangu_pipeline.py --routes output/routes.json
  
  # Start from Phase 4 with existing ACDG
  python pangu_pipeline.py --acdg output/firmware_acdg.json
  
  # Run Phase 3 only (Logic Decoupling)
  python pangu_pipeline.py --routes output/routes.json --only-phase 3
        """
    )
    
    parser.add_argument("--routes", "-r", help="Path to routes JSON file (skip Phase 2)")
    parser.add_argument("--acdg", "-a", help="Path to ACDG JSON file (skip Phase 3)")
    parser.add_argument("--output", "-o", default="output", help="Output directory")
    parser.add_argument("--host", default="localhost", help="IDA Pro host")
    parser.add_argument("--port", type=int, default=18811, help="IDA Pro port")
    parser.add_argument("--only-phase", type=int, choices=[2, 3, 4], 
                        help="Run only specified phase")
    parser.add_argument("--quiet", "-q", action="store_true", help="Less verbose output")
    
    args = parser.parse_args()
    
    # Initialize pipeline
    pipeline = PANGUPipeline(args.host, args.port)
    pipeline.output_dir = args.output
    pipeline.verbose = not args.quiet
    
    # Run
    if args.only_phase:
        # Single phase run
        if not pipeline.check_connection():
            sys.exit(1)
        
        if args.only_phase == 2:
            pipeline.phase2_route_extraction(args.routes)
        elif args.only_phase == 3:
            pipeline.phase2_route_extraction(args.routes)  # Need to load routes first
            pipeline.phase3_logic_decoupling()
        elif args.only_phase == 4:
            pipeline.phase4_dual_agent_detection(args.acdg)
    else:
        # Full pipeline
        pipeline.run_full_pipeline(
            routes_json=args.routes,
            acdg_path=args.acdg
        )


if __name__ == "__main__":
    main()
