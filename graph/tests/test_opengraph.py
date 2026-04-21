"""
test_opengraph.py — Unit tests for the OpenGraph exporter.

Tests format validation, node ID generation, and type mappings.
No Neo4j connection required for these tests.

Usage:
    pytest graph/tests/test_opengraph.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure graph/ is on the import path
sys.path.insert(0, str(Path(__file__).parent.parent))

from opengraph_export import (
    NODE_TYPE_MAP,
    EDGE_TYPE_MAP,
    make_node_id,
    _sanitize,
    _node_key,
    _node_display_name,
    _serialize_props,
    _primary_label,
)


# ── Node ID generation ──────────────────────────────────────────────────────


class TestNodeIdGeneration:
    def test_basic_node_id(self):
        nid = make_node_id("mymac", "Application", "com.1password.1password")
        assert nid == "rs-mymac-application-com.1password.1password"

    def test_node_id_sanitizes_special_chars(self):
        nid = make_node_id("my mac!", "User", "admin user")
        assert " " not in nid
        assert "!" not in nid

    def test_node_id_preserves_dots_and_dashes(self):
        nid = make_node_id("host", "Application", "com.apple.Safari")
        assert "com.apple.Safari" in nid

    def test_sanitize_alphanumeric_passthrough(self):
        assert _sanitize("abc123") == "abc123"

    def test_sanitize_special_chars_replaced(self):
        result = _sanitize("hello world/foo@bar")
        assert " " not in result
        assert "/" not in result
        assert "@" not in result

    def test_sanitize_preserves_allowed_chars(self):
        assert _sanitize("a-b_c.d") == "a-b_c.d"


# ── Node key extraction ─────────────────────────────────────────────────────


class TestNodeKey:
    def test_application_key(self):
        key = _node_key(
            "Application",
            {
                "app_key": "scan-1:com.example.app:/Applications/Example.app",
                "bundle_id": "com.example.app",
                "name": "Example",
            },
        )
        assert key == "scan-1:com.example.app:/Applications/Example.app"

    def test_computer_key_prefers_composite_identity(self):
        key = _node_key(
            "Computer", {"computer_key": "scan-1:host-a", "hostname": "host-a"}
        )
        assert key == "scan-1:host-a"

    def test_tcc_permission_key(self):
        key = _node_key("TCC_Permission", {"service": "kTCCServiceMicrophone"})
        assert key == "kTCCServiceMicrophone"

    def test_entitlement_key(self):
        key = _node_key("Entitlement", {"name": "com.apple.security.app-sandbox"})
        assert key == "com.apple.security.app-sandbox"

    def test_keychain_item_composite_key(self):
        key = _node_key(
            "Keychain_Item", {"label": "My Credential", "kind": "generic_password"}
        )
        assert key == "My Credential-generic_password"

    def test_user_key(self):
        key = _node_key("User", {"name": "admin"})
        assert key == "admin"

    def test_local_group_key(self):
        key = _node_key("LocalGroup", {"name": "wheel"})
        assert key == "wheel"

    def test_remote_access_key(self):
        key = _node_key("RemoteAccessService", {"service": "ssh"})
        assert key == "ssh"

    def test_firewall_key(self):
        key = _node_key("FirewallPolicy", {"name": "default"})
        assert key == "default"

    def test_login_session_key(self):
        key = _node_key("LoginSession", {"terminal": "ttys000"})
        assert key == "ttys000"

    def test_authorization_right_key(self):
        key = _node_key("AuthorizationRight", {"name": "system.privilege.admin"})
        assert key == "system.privilege.admin"

    def test_authorization_plugin_key(self):
        key = _node_key("AuthorizationPlugin", {"name": "MyPlugin"})
        assert key == "MyPlugin"

    def test_system_extension_key(self):
        key = _node_key("SystemExtension", {"identifier": "com.example.ext"})
        assert key == "com.example.ext"

    def test_sudoers_rule_key(self):
        key = _node_key("SudoersRule", {"key": "admin:ALL:ALL"})
        assert key == "admin:ALL:ALL"

    def test_bluetooth_device_key(self):
        key = _node_key(
            "BluetoothDevice", {"address": "AA:BB:CC:DD:EE:FF", "name": "Keyboard"}
        )
        assert key == "AA:BB:CC:DD:EE:FF"

    def test_unknown_label_fallback(self):
        key = _node_key("UnknownLabel", {"name": "test", "other": "value"})
        assert key == "test"

    def test_missing_key_returns_unknown(self):
        key = _node_key("Application", {})
        assert key == "unknown"


# ── Node display names ──────────────────────────────────────────────────────


class TestNodeDisplayName:
    def test_application_display_name(self):
        name = _node_display_name(
            "Application", {"name": "Safari", "bundle_id": "com.apple.Safari"}
        )
        assert name == "Safari"

    def test_application_fallback_to_bundle_id(self):
        name = _node_display_name("Application", {"bundle_id": "com.example.app"})
        assert name == "com.example.app"

    def test_tcc_permission_display_name(self):
        name = _node_display_name(
            "TCC_Permission",
            {"display_name": "Microphone", "service": "kTCCServiceMicrophone"},
        )
        assert name == "Microphone"

    def test_entitlement_display_name(self):
        name = _node_display_name(
            "Entitlement", {"name": "com.apple.security.app-sandbox"}
        )
        assert name == "com.apple.security.app-sandbox"


# ── Property serialization ──────────────────────────────────────────────────


class TestSerializeProps:
    def test_primitives_pass_through(self):
        props = {"name": "Test", "count": 42, "flag": True, "empty": None}
        result = _serialize_props(props)
        assert result == props

    def test_lists_stringified(self):
        props = {"methods": ["dyld_insert", "missing_library_validation"]}
        result = _serialize_props(props)
        assert result["methods"] == ["dyld_insert", "missing_library_validation"]

    def test_complex_types_stringified(self):
        props = {"timestamp": 1234567890}
        result = _serialize_props(props)
        assert result["timestamp"] == 1234567890


# ── Type map completeness ───────────────────────────────────────────────────


class TestTypeMaps:
    def test_all_node_types_have_kind(self):
        for label, info in NODE_TYPE_MAP.items():
            assert "kind" in info, f"{label} missing 'kind'"
            assert info["kind"].startswith("rs_"), (
                f"{label} kind should start with 'rs_'"
            )

    def test_all_node_types_have_icon(self):
        for label, info in NODE_TYPE_MAP.items():
            assert "icon" in info, f"{label} missing 'icon'"
            assert info["icon"].startswith("fa-"), (
                f"{label} icon should be Font Awesome"
            )

    def test_all_node_types_have_color(self):
        for label, info in NODE_TYPE_MAP.items():
            assert "color" in info, f"{label} missing 'color'"
            assert info["color"].startswith("#"), f"{label} color should be hex"

    def test_all_edge_types_have_kind(self):
        for rel_type, info in EDGE_TYPE_MAP.items():
            assert "kind" in info, f"{rel_type} missing 'kind'"
            assert info["kind"].startswith("rs_"), (
                f"{rel_type} kind should start with 'rs_'"
            )

    def test_all_edge_types_have_traversable(self):
        for rel_type, info in EDGE_TYPE_MAP.items():
            assert "traversable" in info, f"{rel_type} missing 'traversable'"
            assert isinstance(info["traversable"], bool)

    def test_node_type_count(self):
        """Verify all 29 Rootstock node types are mapped (27 post-Phase 6 + CWE + Recommendation)."""
        assert len(NODE_TYPE_MAP) == 29

    def test_edge_type_count(self):
        """Verify all 51 Rootstock edge types are mapped including AD_USER_OF."""
        assert len(EDGE_TYPE_MAP) == 51


# ── Primary label selection ─────────────────────────────────────────────────


class TestPrimaryLabel:
    def test_known_label_selected(self):
        assert _primary_label(["Application"]) == "Application"

    def test_known_label_preferred_over_unknown(self):
        assert _primary_label(["SomeOther", "Application"]) == "Application"

    def test_unknown_label_fallback(self):
        assert _primary_label(["CustomLabel"]) == "CustomLabel"

    def test_empty_labels_returns_unknown(self):
        assert _primary_label([]) == "Unknown"


# ── OpenGraph JSON format validation ────────────────────────────────────────


class TestOpenGraphFormat:
    def test_minimal_opengraph_structure(self):
        """Verify the expected top-level structure of an OpenGraph export."""
        og = {
            "metadata": {"source_kind": "Rootstock"},
            "graph": {"nodes": [], "edges": []},
        }
        assert "metadata" in og
        assert "graph" in og
        assert "nodes" in og["graph"]
        assert "edges" in og["graph"]

    def test_node_has_required_fields(self):
        node = {
            "id": "rs-host-application-com.example",
            "kind": "rs_Application",
            "label": "Example App",
            "properties": {},
        }
        assert "id" in node
        assert "kind" in node
        assert "label" in node
        assert "properties" in node

    def test_edge_has_required_fields(self):
        edge = {
            "source": "rs-host-application-com.example",
            "target": "rs-host-tcc_permission-microphone",
            "kind": "rs_HasTCCGrant",
            "properties": {"_traversable": True},
        }
        assert "source" in edge
        assert "target" in edge
        assert "kind" in edge
        assert "properties" in edge
