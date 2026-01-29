# tests/test_pipeline_offline.py
# Offline test PANGU Pipeline (no IDA connection required)
# Test loading from existing route JSON files and generating ACDG

import sys
import os
import json

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime
from analysis.models import ACDG, RouteNode, AuthState, ProtectionType


def load_routes_from_json(json_path: str) -> list:
    """Load route data from existing route JSON"""
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    routes = []
    
    # Handle direct array format (TEW-811DRU etc.)
    if isinstance(data, list):
        for item in data:
            routes.append({
                "path": item.get("full_path", item.get("path", "")),
                "sub_path": item.get("sub_path", ""),
                "handler": item.get("handler", ""),
                "source_hub": item.get("source_hub", ""),
                "source_type": item.get("source_type", "unknown"),
                "root": item.get("root", "/")
            })
    # Handle hierarchical format (root -> routes)
    elif isinstance(data, dict) and all(k.startswith('/') or k == '/' for k in data.keys()):
        for root, items in data.items():
            for item in items:
                routes.append({
                    "path": item.get("full_path", item.get("path", "")),
                    "sub_path": item.get("path", item.get("sub_path", "")),
                    "handler": item.get("handler", ""),
                    "source_hub": item.get("source_hub", ""),
                    "source_type": "hierarchical",
                    "root": root
                })
    # Handle hubs format
    elif "hubs" in data:
        for hub in data["hubs"]:
            hub_name = hub.get("hub_name", hub.get("hub_address", ""))
            hub_type = hub.get("hub_type", "unknown")
            for route in hub.get("routes", []):
                routes.append({
                    "path": route.get("full_path", route.get("path", "")),
                    "sub_path": route.get("sub_path", ""),
                    "handler": route.get("handler", ""),
                    "source_hub": hub_name,
                    "source_type": hub_type,
                    "root": route.get("root", "/")
                })
    # Handle flat list format
    elif "routes" in data:
        for route in data["routes"]:
            routes.append({
                "path": route.get("full_path", route.get("path", "")),
                "sub_path": route.get("sub_path", ""),
                "handler": route.get("handler", ""),
                "source_hub": route.get("source_hub", ""),
                "source_type": route.get("source_type", "unknown"),
                "root": route.get("root", "/")
            })
    
    return routes


def create_mock_acdg_from_routes(routes: list, firmware_name: str) -> ACDG:
    """
    Create ACDG from route list (offline mode, using heuristic rules)
    
    Offline mode rules:
    - Routes containing cgi-bin are marked for inspection
    - Handlers with sensitive keywords are marked as high risk
    - Others are marked as Unknown
    """
    acdg = ACDG()
    acdg.firmware_name = firmware_name
    acdg.analysis_timestamp = datetime.now().isoformat()
    
    # Sensitive keywords
    sensitive_keywords = [
        "system", "exec", "cmd", "command", "ping", "reboot",
        "config", "password", "upload", "download", "backup",
        "nvram", "telnet", "ssh", "firmware", "update"
    ]
    
    # Possible authentication-related routes
    auth_keywords = ["login", "logout", "session", "auth", "check"]
    
    for r in routes:
        path = r.get("path", "")
        handler = r.get("handler", "")
        
        node = RouteNode(
            path=path,
            sub_path=r.get("sub_path", ""),
            handler=handler,
            source_hub=r.get("source_hub", ""),
            source_type=r.get("source_type", "unknown"),
            root=r.get("root", "/")
        )
        
        # Heuristic judgment
        path_lower = path.lower()
        handler_lower = handler.lower() if handler else ""
        
        # Check if possibly sensitive operation
        is_sensitive = any(kw in path_lower or kw in handler_lower 
                          for kw in sensitive_keywords)
        
        # Check if it looks like authentication-related
        is_auth_related = any(kw in path_lower or kw in handler_lower 
                             for kw in auth_keywords)
        
        if is_auth_related:
            # Authentication-related routes may be Auth-Free (login pages)
            node.auth_state = AuthState.AUTH_FREE
            node.protection_type = ProtectionType.NONE
        elif is_sensitive:
            # Sensitive operations, mark for further inspection
            node.auth_state = AuthState.UNKNOWN
            node.has_sensitive_sink = True
            node.sensitive_sinks = [kw for kw in sensitive_keywords 
                                   if kw in path_lower or kw in handler_lower]
        else:
            # Other routes marked as unknown
            node.auth_state = AuthState.UNKNOWN
        
        acdg.add_route(node)
    
    return acdg


def test_load_real_routes():
    """Test loading real route data"""
    print("\n" + "=" * 60)
    print("TEST: Load Real Routes from JSON")
    print("=" * 60)
    
    test_files = [
        "output/2025.12.11_Dlink_823G_routes_v3_hierarchical.json",
        "output/2025.12.13_TEW-811DRU_routes_v3_latest.json"
    ]
    
    for filepath in test_files:
        if not os.path.exists(filepath):
            print(f"  [SKIP] File not found: {filepath}")
            continue
        
        print(f"\n  Testing: {filepath}")
        
        routes = load_routes_from_json(filepath)
        print(f"    Loaded {len(routes)} routes")
        
        # Display first 5 routes
        for i, r in enumerate(routes[:5]):
            print(f"      [{i+1}] {r['path']} -> {r['handler']}")
        if len(routes) > 5:
            print(f"      ... and {len(routes) - 5} more")
        
        # Create ACDG
        firmware_name = os.path.basename(filepath).split('_')[1]
        acdg = create_mock_acdg_from_routes(routes, firmware_name)
        
        print(f"\n    ACDG Summary:")
        print(f"      Total Routes: {acdg.total_routes}")
        print(f"      Auth-Free: {acdg.auth_free_count}")
        print(f"      Auth-Required: {acdg.auth_required_count}")
        print(f"      Unknown: {acdg.unknown_count}")
        
        # Display sensitive routes
        sensitive_routes = [r for r in acdg.routes if r.has_sensitive_sink]
        if sensitive_routes:
            print(f"\n    Sensitive Routes ({len(sensitive_routes)}):")
            for r in sensitive_routes[:10]:
                print(f"      - {r.path} -> {r.handler}")
                print(f"        Sinks: {r.sensitive_sinks}")
        
        # Save ACDG
        output_path = f"output/test_{firmware_name}_acdg.json"
        acdg.save_json(output_path)
        print(f"\n    [OK] Saved to: {output_path}")


def test_acdg_operations():
    """Test ACDG data structure operations"""
    print("\n" + "=" * 60)
    print("TEST: ACDG Operations")
    print("=" * 60)
    
    acdg = ACDG()
    acdg.firmware_name = "TestFirmware"
    
    # Add routes
    routes_data = [
        ("/login", "handle_login", AuthState.AUTH_FREE),
        ("/admin/config", "admin_config", AuthState.AUTH_REQUIRED),
        ("/api/system/reboot", "do_reboot", AuthState.AUTH_FREE),  # Potential vulnerability
        ("/api/data", "get_data", AuthState.AUTH_REQUIRED),
    ]
    
    for path, handler, auth_state in routes_data:
        node = RouteNode(
            path=path,
            sub_path=path.split('/')[-1],
            handler=handler,
            source_hub="main",
            auth_state=auth_state
        )
        acdg.add_route(node)
    
    print(f"\n  Created ACDG with {acdg.total_routes} routes")
    
    # Test filtering
    auth_free = acdg.get_auth_free_routes()
    print(f"\n  Auth-Free Routes: {len(auth_free)}")
    for r in auth_free:
        print(f"    - {r.path} -> {r.handler}")
    
    # Test serialization
    test_path = "output/test_operations_acdg.json"
    acdg.save_json(test_path)
    print(f"\n  [OK] Saved to: {test_path}")
    
    # Test loading
    loaded = ACDG.load_json(test_path)
    assert loaded.total_routes == acdg.total_routes
    print(f"  [OK] Loaded successfully, {loaded.total_routes} routes")


def main():
    """Run all offline tests"""
    os.makedirs("output", exist_ok=True)
    
    print("\n" + "=" * 70)
    print(" PANGU Pipeline Offline Tests")
    print(" Testing route loading and ACDG generation")
    print("=" * 70)
    
    test_acdg_operations()
    test_load_real_routes()
    
    print("\n" + "=" * 70)
    print(" All offline tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()
