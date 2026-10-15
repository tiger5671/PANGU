# Copyright (c) 2026 The Pangu Project Authors. All rights reserved.
# analysis/models.py
"""
PANGU Data Model Definitions
Including ACDG (Access Control Dependency Graph) and other core data structures
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Literal
from enum import Enum
import json


class AuthState(Enum):
    """Authentication State Enumeration"""
    AUTH_REQUIRED = "Auth-Required"    # Authentication required
    AUTH_FREE = "Auth-Free"            # No authentication required
    UNKNOWN = "Unknown"                # Unknown state


class ProtectionType(Enum):
    """Protection Type Enumeration"""
    GATEKEEPER = "Gatekeeper"          # Gatekeeper protection (global authentication)
    SHARED_UTILITY = "SharedUtility"   # Shared authentication utility function
    INLINE_CHECK = "InlineCheck"       # Inline authentication check
    GLOBAL_FLAG = "GlobalFlag"         # Global flag check
    NONE = "None"                      # No protection


@dataclass
class RouteNode:
    """Route Node"""
    path: str                                    # Full path
    sub_path: str                               # Sub-path
    handler: str                                # Handler function
    source_hub: str                             # Source hub
    source_type: str = "unknown"                # Source type
    root: str = "/"                             # Root path
    
    # Authentication related
    auth_state: AuthState = AuthState.UNKNOWN
    protection_type: ProtectionType = ProtectionType.NONE
    protection_detail: Optional[str] = None
    
    # Analysis metadata
    tis_score: Optional[float] = None           # TIS score
    has_sensitive_sink: bool = False            # Whether contains sensitive operations
    sensitive_sinks: List[str] = field(default_factory=list)
    # Check presence and effectiveness are separate. Empty references or gaps
    # must never be interpreted as a proof that the route is safe.
    auth_refs: List[Dict] = field(default_factory=list)
    analysis_gaps: List[str] = field(default_factory=list)
    binary_id: str = ""
    http_method: str = ""
    selector: Dict = field(default_factory=dict)
    mount_chain: List[Dict] = field(default_factory=list)
    route_resolved: bool = False
    dispatch_function: str = ""
    dispatch_address: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "path": self.path,
            "sub_path": self.sub_path,
            "handler": self.handler,
            "source_hub": self.source_hub,
            "source_type": self.source_type,
            "root": self.root,
            "auth_state": self.auth_state.value,
            "protection_type": self.protection_type.value,
            "protection_detail": self.protection_detail,
            "tis_score": self.tis_score,
            "has_sensitive_sink": self.has_sensitive_sink,
            "sensitive_sinks": self.sensitive_sinks,
            "auth_refs": self.auth_refs, "analysis_gaps": self.analysis_gaps,
            "binary_id": self.binary_id, "http_method": self.http_method,
            "selector": self.selector, "mount_chain": self.mount_chain,
            "route_resolved": self.route_resolved,
            "dispatch_function": self.dispatch_function, "dispatch_address": self.dispatch_address
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "RouteNode":
        """Create from dictionary"""
        return cls(
            path=data.get("full_path", data.get("path", "")),
            sub_path=data.get("sub_path", ""),
            handler=data.get("handler", ""),
            source_hub=data.get("source_hub", ""),
            source_type=data.get("source_type", "unknown"),
            root=data.get("root", "/"),
            auth_state=AuthState(data.get("auth_state", "Unknown")),
            protection_type=ProtectionType(data.get("protection_type", "None")),
            protection_detail=data.get("protection_detail"),
            tis_score=data.get("tis_score"),
            has_sensitive_sink=data.get("has_sensitive_sink", False),
            sensitive_sinks=data.get("sensitive_sinks", []),
            auth_refs=data.get("auth_refs", []), analysis_gaps=data.get("analysis_gaps", []),
            binary_id=data.get("binary_id", ""), http_method=data.get("http_method", ""),
            selector=data.get("selector", {}), mount_chain=data.get("mount_chain", []),
            route_resolved=data.get("route_resolved", False),
            dispatch_function=data.get("dispatch_function", ""), dispatch_address=data.get("dispatch_address", "")
        )


@dataclass
class AuthMechanism:
    """Authentication Mechanism"""
    address: str                                # Function/code address
    name: str                                   # Function name
    mechanism_type: str                         # Type: "function", "inline", "global_flag"
    confidence: float = 0.0                     # Confidence 0.0-1.0
    description: str = ""                       # Description
    
    # Analysis source
    detection_method: str = ""                  # Detection method
    tis_score: Optional[float] = None
    keywords_matched: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    applies_to: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ACDG:
    """
    Access Control Dependency Graph (ACDG)
    Core data structure integrating route topology and authentication logic
    """
    # Route nodes
    routes: List[RouteNode] = field(default_factory=list)
    
    # Authentication mechanisms
    global_auth_mechanisms: List[AuthMechanism] = field(default_factory=list)
    shared_auth_utilities: List[AuthMechanism] = field(default_factory=list)
    
    # Statistics
    total_routes: int = 0
    auth_required_count: int = 0
    auth_free_count: int = 0
    unknown_count: int = 0
    
    # Metadata
    firmware_name: str = ""
    analysis_timestamp: str = ""
    routing_edges: List[Dict] = field(default_factory=list)
    binary_id: str = ""

    def __post_init__(self):
        self._update_stats()
    
    def add_route(self, route: RouteNode):
        """Add a route node"""
        self.routes.append(route)
        self.total_routes += 1
        self.auth_required_count += route.auth_state == AuthState.AUTH_REQUIRED
        self.auth_free_count += route.auth_state == AuthState.AUTH_FREE
        self.unknown_count += route.auth_state == AuthState.UNKNOWN
    
    def add_global_auth(self, mechanism: AuthMechanism):
        """Add a global authentication mechanism"""
        self.global_auth_mechanisms.append(mechanism)
    
    def add_shared_utility(self, mechanism: AuthMechanism):
        """Add a shared authentication utility"""
        self.shared_auth_utilities.append(mechanism)
    
    def _update_stats(self):
        """Update statistics"""
        self.total_routes = len(self.routes)
        self.auth_required_count = sum(1 for r in self.routes if r.auth_state == AuthState.AUTH_REQUIRED)
        self.auth_free_count = sum(1 for r in self.routes if r.auth_state == AuthState.AUTH_FREE)
        self.unknown_count = sum(1 for r in self.routes if r.auth_state == AuthState.UNKNOWN)
    
    def get_auth_free_routes(self) -> List[RouteNode]:
        """Get all auth-free routes (high risk)"""
        return [r for r in self.routes if r.auth_state == AuthState.AUTH_FREE]
    
    def get_sensitive_auth_free_routes(self) -> List[RouteNode]:
        """Get auth-free routes containing sensitive operations (highest risk)"""
        return [r for r in self.routes 
                if r.auth_state == AuthState.AUTH_FREE and r.has_sensitive_sink]
    
    def get_routes_by_hub(self, hub_addr: str) -> List[RouteNode]:
        """Get routes by hub"""
        hub_lower = hub_addr.lower()
        return [r for r in self.routes if r.source_hub.lower() == hub_lower]
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        self._update_stats()
        return {
            "schema_version": 2,
            "metadata": {
                "firmware_name": self.firmware_name,
                "binary_id": self.binary_id,
                "analysis_timestamp": self.analysis_timestamp,
                "total_routes": self.total_routes,
                "auth_required_count": self.auth_required_count,
                "auth_free_count": self.auth_free_count,
                "unknown_count": self.unknown_count
            },
            "global_auth_mechanisms": [m.to_dict() for m in self.global_auth_mechanisms],
            "shared_auth_utilities": [m.to_dict() for m in self.shared_auth_utilities],
            "routes": [r.to_dict() for r in self.routes],
            "routing_edges": self.routing_edges
        }
    
    def save_json(self, filepath: str):
        """Save as JSON file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
    
    @classmethod
    def load_json(cls, filepath: str) -> "ACDG":
        """Load from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        acdg = cls()
        
        # Load metadata
        meta = data.get("metadata", {})
        acdg.firmware_name = meta.get("firmware_name", "")
        acdg.binary_id = meta.get("binary_id", "")
        acdg.analysis_timestamp = meta.get("analysis_timestamp", "")
        acdg.routing_edges = data.get("routing_edges", [])
        
        # Load authentication mechanisms
        for m in data.get("global_auth_mechanisms", []):
            acdg.global_auth_mechanisms.append(AuthMechanism(**m))
        
        for m in data.get("shared_auth_utilities", []):
            acdg.shared_auth_utilities.append(AuthMechanism(**m))
        
        # Load routes
        for r in data.get("routes", []):
            acdg.routes.append(RouteNode.from_dict(r))
        
        acdg._update_stats()
        return acdg
    
    def print_summary(self):
        """Print summary"""
        self._update_stats()
        print("\n" + "=" * 60)
        print("ACDG Summary")
        print("=" * 60)
        print(f"Firmware: {self.firmware_name}")
        print(f"Timestamp: {self.analysis_timestamp}")
        print("-" * 60)
        print(f"Total Routes: {self.total_routes}")
        print(f"  - Auth-Required: {self.auth_required_count}")
        print(f"  - Auth-Free: {self.auth_free_count} (HIGH RISK)")
        print(f"  - Unknown: {self.unknown_count}")
        print("-" * 60)
        print(f"Global Auth Mechanisms: {len(self.global_auth_mechanisms)}")
        for m in self.global_auth_mechanisms:
            print(f"  - {m.name} @ {m.address} (conf: {m.confidence:.2f})")
        print(f"Shared Auth Utilities: {len(self.shared_auth_utilities)}")
        for m in self.shared_auth_utilities:
            print(f"  - {m.name} @ {m.address}")
        print("=" * 60)


@dataclass
class VulnerabilityFinding:
    """Vulnerability Finding"""
    route: RouteNode                            # Associated route
    vuln_type: str                              # Vulnerability type
    cwe_id: str                                 # CWE identifier
    confidence: Literal["HIGH", "MEDIUM", "LOW"] = "LOW"
    description: str = ""
    evidence: str = ""                          # Code evidence
    
    # Detective related
    detective_reasoning: str = ""               # Detective's reasoning
    
    # Reviewer related
    reviewer_verdict: str = ""                  # Reviewer's verdict
    severity: Optional[str] = None              # Severity: CRITICAL/HIGH/MEDIUM/LOW
    attack_vector: str = ""                     # Attack vector description
    counterfactual_analysis: Dict = field(default_factory=dict)  # Counterfactual analysis result
    evidence_records: List[Dict] = field(default_factory=list)
    review_status: str = "UNRESOLVED"
    
    def to_dict(self) -> dict:
        return {
            "route_path": self.route.path,
            "handler": self.route.handler,
            "vuln_type": self.vuln_type,
            "cwe_id": self.cwe_id,
            "confidence": self.confidence,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "attack_vector": self.attack_vector,
            "detective_reasoning": self.detective_reasoning,
            "reviewer_verdict": self.reviewer_verdict,
            "counterfactual_analysis": self.counterfactual_analysis,
            "evidence_records": self.evidence_records,
            "review_status": self.review_status
        }


@dataclass
class AnalysisReport:
    """Analysis Report"""
    firmware_name: str = ""
    analysis_timestamp: str = ""
    total_routes: int = 0
    auth_free_routes: int = 0
    auth_required_routes: int = 0
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    duration_seconds: float = 0.0
    unresolved_findings: List[VulnerabilityFinding] = field(default_factory=list)
    coverage: Dict = field(default_factory=dict)
    
    def add_finding(self, finding: VulnerabilityFinding):
        self.findings.append(finding)
    
    def get_high_confidence_vulns(self) -> List[VulnerabilityFinding]:
        return [v for v in self.findings if v.confidence == "HIGH"]
    
    def get_critical_vulns(self) -> List[VulnerabilityFinding]:
        return [v for v in self.findings if v.severity == "CRITICAL"]
    
    def to_dict(self) -> dict:
        return {
            "metadata": {
                "firmware_name": self.firmware_name,
                "analysis_timestamp": self.analysis_timestamp,
                "duration_seconds": self.duration_seconds
            },
            "route_summary": {
                "total_routes": self.total_routes,
                "auth_free_routes": self.auth_free_routes,
                "auth_required_routes": self.auth_required_routes
            },
            "vulnerability_summary": {
                "total_findings": len(self.findings),
                "high_confidence": len(self.get_high_confidence_vulns()),
                "critical": len(self.get_critical_vulns())
            },
            "findings": [v.to_dict() for v in self.findings],
            "unresolved_findings": [v.to_dict() for v in self.unresolved_findings],
            "coverage": self.coverage
        }
    
    def save_json(self, filepath: str):
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
