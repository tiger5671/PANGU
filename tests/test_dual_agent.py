# tests/test_dual_agent.py
# PANGU Dual-Agent System End-to-End Tests
# Test Detective + Reviewer collaborative detection workflow

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime
from analysis.models import ACDG, RouteNode, AuthMechanism, AuthState, ProtectionType
from analysis.dual_agent_detector import DualAgentDetector


def create_mock_acdg() -> ACDG:
    """Create test ACDG"""
    acdg = ACDG()
    acdg.firmware_name = "Test_Firmware"
    acdg.analysis_timestamp = datetime.now().isoformat()
    
    # Add some mock routes
    # Auth-Free routes (high risk)
    auth_free_routes = [
        RouteNode(
            path="/cgi-bin/config_backup.cgi",
            sub_path="config_backup.cgi",
            handler="config_backup_handler",
            source_hub="main_cgi_handler",
            source_type="cgi",
            auth_state=AuthState.AUTH_FREE,
            protection_type=ProtectionType.NONE,
            has_sensitive_sink=True,
            sensitive_sinks=["rce:system", "file_read:fopen"]
        ),
        RouteNode(
            path="/goform/setWanConfig",
            sub_path="setWanConfig",
            handler="formSetWanConfig",
            source_hub="goform_dispatch",
            source_type="goform",
            auth_state=AuthState.AUTH_FREE,
            protection_type=ProtectionType.NONE,
            has_sensitive_sink=True,
            sensitive_sinks=["config_mod:nvram_set"]
        ),
        RouteNode(
            path="/goform/execCommand",
            sub_path="execCommand",
            handler="formExecCommand",
            source_hub="goform_dispatch",
            source_type="goform",
            auth_state=AuthState.AUTH_FREE,
            protection_type=ProtectionType.NONE,
            has_sensitive_sink=True,
            sensitive_sinks=["rce:doSystemCmd", "rce:system"]
        ),
    ]
    
    # Auth-Required routes (low risk)
    auth_required_routes = [
        RouteNode(
            path="/goform/setPassword",
            sub_path="setPassword",
            handler="formSetPassword",
            source_hub="goform_dispatch",
            source_type="goform",
            auth_state=AuthState.AUTH_REQUIRED,
            protection_type=ProtectionType.GATEKEEPER,
            protection_detail="GetLoginStatus"
        ),
        RouteNode(
            path="/goform/reboot",
            sub_path="reboot",
            handler="formReboot",
            source_hub="goform_dispatch",
            source_type="goform",
            auth_state=AuthState.AUTH_REQUIRED,
            protection_type=ProtectionType.SHARED_UTILITY,
            protection_detail="check_session"
        ),
    ]
    
    for route in auth_free_routes + auth_required_routes:
        acdg.add_route(route)
    
    # Add global authentication mechanisms
    acdg.add_global_auth(AuthMechanism(
        address="0x00408000",
        name="GetLoginStatus",
        mechanism_type="function",
        confidence=0.95,
        description="Main login status checker"
    ))
    
    acdg.add_shared_utility(AuthMechanism(
        address="0x00409000",
        name="check_session",
        mechanism_type="function",
        confidence=0.85,
        description="Session validation utility"
    ))
    
    return acdg


def test_acdg_creation():
    """Test ACDG creation and saving"""
    print("\n" + "=" * 60)
    print("TEST: ACDG Creation and Serialization")
    print("=" * 60)
    
    acdg = create_mock_acdg()
    
    # Print summary
    acdg.print_summary()
    
    # Test save and load
    test_path = "output/test_acdg.json"
    acdg.save_json(test_path)
    print(f"\n[OK] Saved ACDG to {test_path}")
    
    # Reload
    loaded_acdg = ACDG.load_json(test_path)
    print(f"[OK] Loaded ACDG - {loaded_acdg.total_routes} routes")
    
    # Verify
    assert loaded_acdg.total_routes == acdg.total_routes
    assert len(loaded_acdg.get_auth_free_routes()) == len(acdg.get_auth_free_routes())
    print("[OK] Serialization test passed!")


def test_offline_detector():
    """
    Offline test DualAgentDetector (without IDA connection)
    Only test initialization and ACDG loading
    """
    print("\n" + "=" * 60)
    print("TEST: Offline Dual-Agent Detector")
    print("=" * 60)
    
    # Create and save test ACDG
    acdg = create_mock_acdg()
    test_path = "output/test_acdg.json"
    acdg.save_json(test_path)
    
    # Initialize detector (without IDA connection)
    detector = DualAgentDetector()
    
    # Load ACDG
    result = detector.load_acdg(test_path)
    print(f"[{'OK' if result else 'FAIL'}] Load ACDG: {result}")
    
    # Check status
    if detector.acdg:
        auth_free = detector.acdg.get_auth_free_routes()
        print(f"[INFO] Auth-Free routes: {len(auth_free)}")
        for route in auth_free:
            print(f"       - {route.path} -> {route.handler}")
            if route.sensitive_sinks:
                print(f"         Sensitive: {route.sensitive_sinks}")
    
    print("[OK] Offline detector test passed!")


def test_with_ida():
    """
    Full test (requires IDA connection)
    """
    print("\n" + "=" * 60)
    print("TEST: Full Dual-Agent Detection (requires IDA)")
    print("=" * 60)
    
    # Create test ACDG
    acdg = create_mock_acdg()
    test_path = "output/test_acdg.json"
    acdg.save_json(test_path)
    
    # Initialize detector
    detector = DualAgentDetector()
    detector.load_acdg(test_path)
    
    # Check IDA connection
    if not detector.check_ida_connection():
        print("[SKIP] IDA Pro not connected, skipping live test")
        print("       To run this test, ensure IDA Pro is running with ida_server.py")
        return
    
    # Run detection
    print("\n[*] Starting Dual-Agent detection...")
    try:
        report = detector.run("output")
        print(f"\n[OK] Detection complete!")
        print(f"     Findings: {len(report.findings)}")
    except Exception as e:
        print(f"[ERROR] Detection failed: {e}")
        import traceback
        traceback.print_exc()


def test_interactive_mode():
    """
    Test interactive mode
    """
    print("\n" + "=" * 60)
    print("TEST: Interactive Single-Route Analysis")
    print("=" * 60)
    
    # Create test ACDG
    acdg = create_mock_acdg()
    
    # Initialize detector
    detector = DualAgentDetector()
    detector.set_acdg(acdg)
    
    # Check IDA connection
    if not detector.check_ida_connection():
        print("[SKIP] IDA Pro not connected")
        return
    
    # Interactive single route analysis
    target_route = "/goform/execCommand"
    print(f"\n[*] Analyzing route: {target_route}")
    
    finding = detector.run_interactive(target_route)
    
    if finding:
        print(f"\n[RESULT] Vulnerability found!")
        print(f"         Type: {finding.vuln_type}")
        print(f"         CWE: {finding.cwe_id}")
        print(f"         Severity: {finding.severity}")


def main():
    """Run all tests"""
    import os
    os.makedirs("output", exist_ok=True)
    
    print("\n" + "=" * 70)
    print(" PANGU Dual-Agent System Tests")
    print("=" * 70)
    
    # Basic tests (no IDA required)
    test_acdg_creation()
    test_offline_detector()
    
    # Full tests (IDA required)
    print("\n" + "-" * 70)
    print("The following tests require IDA Pro connection:")
    print("-" * 70)
    
    test_with_ida()
    test_interactive_mode()
    
    print("\n" + "=" * 70)
    print(" All tests completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()
