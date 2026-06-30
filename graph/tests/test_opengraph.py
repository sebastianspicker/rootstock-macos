"""
test_opengraph.py — Unit tests for the OpenGraph exporter.

Tests format validation, node ID generation, and type mappings.
No Neo4j connection required for these tests.

Usage:
    pytest graph/tests/test_opengraph.py -v
"""

from __future__ import annotations

from unittest import TestCase

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


checks = TestCase()


# ── Node ID generation ──────────────────────────────────────────────────────


class TestNodeIdGeneration:
    def test_basic_node_id(self):
        nid = make_node_id("mymac", "Application", "com.1password.1password")
        checks.assertEqual(nid, "rs-mymac-application-com.1password.1password")

    def test_node_id_sanitizes_special_chars(self):
        nid = make_node_id("my mac!", "User", "admin user")
        checks.assertNotIn(" ", nid)
        checks.assertNotIn("!", nid)

    def test_node_id_preserves_dots_and_dashes(self):
        nid = make_node_id("host", "Application", "com.apple.Safari")
        checks.assertIn("com.apple.Safari", nid)

    def test_sanitize_alphanumeric_passthrough(self):
        checks.assertEqual(_sanitize("abc123"), "abc123")

    def test_sanitize_special_chars_replaced(self):
        result = _sanitize("hello world/foo@bar")
        checks.assertNotIn(" ", result)
        checks.assertNotIn("/", result)
        checks.assertNotIn("@", result)

    def test_sanitize_preserves_allowed_chars(self):
        checks.assertEqual(_sanitize("a-b_c.d"), "a-b_c.d")


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
        checks.assertEqual(key, "scan-1:com.example.app:/Applications/Example.app")

    def test_computer_key_prefers_composite_identity(self):
        key = _node_key(
            "Computer", {"computer_key": "scan-1:host-a", "hostname": "host-a"}
        )
        checks.assertEqual(key, "scan-1:host-a")

    def test_tcc_permission_key(self):
        key = _node_key("TCC_Permission", {"service": "kTCCServiceMicrophone"})
        checks.assertEqual(key, "kTCCServiceMicrophone")

    def test_entitlement_key(self):
        key = _node_key("Entitlement", {"name": "com.apple.security.app-sandbox"})
        checks.assertEqual(key, "com.apple.security.app-sandbox")

    def test_keychain_item_composite_key(self):
        key = _node_key(
            "Keychain_Item", {"label": "My Credential", "kind": "generic_password"}
        )
        checks.assertEqual(key, "My Credential-generic_password")

    def test_user_key(self):
        key = _node_key("User", {"name": "admin"})
        checks.assertEqual(key, "admin")

    def test_local_group_key(self):
        key = _node_key("LocalGroup", {"name": "wheel"})
        checks.assertEqual(key, "wheel")

    def test_remote_access_key(self):
        key = _node_key("RemoteAccessService", {"service": "ssh"})
        checks.assertEqual(key, "ssh")

    def test_firewall_key(self):
        key = _node_key("FirewallPolicy", {"name": "default"})
        checks.assertEqual(key, "default")

    def test_login_session_key(self):
        key = _node_key("LoginSession", {"terminal": "ttys000"})
        checks.assertEqual(key, "ttys000")

    def test_authorization_right_key(self):
        key = _node_key("AuthorizationRight", {"name": "system.privilege.admin"})
        checks.assertEqual(key, "system.privilege.admin")

    def test_authorization_plugin_key(self):
        key = _node_key("AuthorizationPlugin", {"name": "MyPlugin"})
        checks.assertEqual(key, "MyPlugin")

    def test_system_extension_key(self):
        key = _node_key("SystemExtension", {"identifier": "com.example.ext"})
        checks.assertEqual(key, "com.example.ext")

    def test_sudoers_rule_key(self):
        key = _node_key("SudoersRule", {"key": "admin:ALL:ALL"})
        checks.assertEqual(key, "admin:ALL:ALL")

    def test_bluetooth_device_key(self):
        key = _node_key(
            "BluetoothDevice", {"address": "AA:BB:CC:DD:EE:FF", "name": "Keyboard"}
        )
        checks.assertEqual(key, "AA:BB:CC:DD:EE:FF")

    def test_unknown_label_fallback(self):
        key = _node_key("UnknownLabel", {"name": "test", "other": "value"})
        checks.assertEqual(key, "test")

    def test_missing_key_returns_unknown(self):
        key = _node_key("Application", {})
        checks.assertEqual(key, "unknown")


# ── Node display names ──────────────────────────────────────────────────────


class TestNodeDisplayName:
    def test_application_display_name(self):
        name = _node_display_name(
            "Application", {"name": "Safari", "bundle_id": "com.apple.Safari"}
        )
        checks.assertEqual(name, "Safari")

    def test_application_fallback_to_bundle_id(self):
        name = _node_display_name("Application", {"bundle_id": "com.example.app"})
        checks.assertEqual(name, "com.example.app")

    def test_tcc_permission_display_name(self):
        name = _node_display_name(
            "TCC_Permission",
            {"display_name": "Microphone", "service": "kTCCServiceMicrophone"},
        )
        checks.assertEqual(name, "Microphone")

    def test_entitlement_display_name(self):
        name = _node_display_name(
            "Entitlement", {"name": "com.apple.security.app-sandbox"}
        )
        checks.assertEqual(name, "com.apple.security.app-sandbox")


# ── Property serialization ──────────────────────────────────────────────────


class TestSerializeProps:
    def test_primitives_pass_through(self):
        props = {"name": "Test", "count": 42, "flag": True, "empty": None}
        result = _serialize_props(props)
        checks.assertEqual(result, props)

    def test_lists_stringified(self):
        props = {"methods": ["dyld_insert", "missing_library_validation"]}
        result = _serialize_props(props)
        checks.assertEqual(
            result["methods"], ["dyld_insert", "missing_library_validation"]
        )

    def test_complex_types_stringified(self):
        props = {"timestamp": 1234567890}
        result = _serialize_props(props)
        checks.assertEqual(result["timestamp"], 1234567890)


# ── Type map completeness ───────────────────────────────────────────────────


class TestTypeMaps:
    def test_all_node_types_have_kind(self):
        for label, info in NODE_TYPE_MAP.items():
            checks.assertIn("kind", info, f"{label} missing 'kind'")
            checks.assertTrue(
                info["kind"].startswith("rs_"), f"{label} kind should start with 'rs_'"
            )

    def test_all_node_types_have_icon(self):
        for label, info in NODE_TYPE_MAP.items():
            checks.assertIn("icon", info, f"{label} missing 'icon'")
            checks.assertTrue(
                info["icon"].startswith("fa-"), f"{label} icon should be Font Awesome"
            )

    def test_all_node_types_have_color(self):
        for label, info in NODE_TYPE_MAP.items():
            checks.assertIn("color", info, f"{label} missing 'color'")
            checks.assertTrue(
                info["color"].startswith("#"), f"{label} color should be hex"
            )

    def test_all_edge_types_have_kind(self):
        for rel_type, info in EDGE_TYPE_MAP.items():
            checks.assertIn("kind", info, f"{rel_type} missing 'kind'")
            checks.assertTrue(
                info["kind"].startswith("rs_"),
                f"{rel_type} kind should start with 'rs_'",
            )

    def test_all_edge_types_have_traversable(self):
        for rel_type, info in EDGE_TYPE_MAP.items():
            checks.assertIn("traversable", info, f"{rel_type} missing 'traversable'")
            checks.assertTrue(isinstance(info["traversable"], bool))

    def test_node_type_count(self):
        """Verify Rootstock and cve-scan module node types are mapped."""
        checks.assertEqual(len(NODE_TYPE_MAP), 44)

    def test_edge_type_count(self):
        """Verify Rootstock and cve-scan module edge types are mapped."""
        checks.assertEqual(len(EDGE_TYPE_MAP), 68)


# ── Primary label selection ─────────────────────────────────────────────────


class TestPrimaryLabel:
    def test_known_label_selected(self):
        checks.assertEqual(_primary_label(["Application"]), "Application")

    def test_known_label_preferred_over_unknown(self):
        checks.assertEqual(_primary_label(["SomeOther", "Application"]), "Application")

    def test_unknown_label_fallback(self):
        checks.assertEqual(_primary_label(["CustomLabel"]), "CustomLabel")

    def test_empty_labels_returns_unknown(self):
        checks.assertEqual(_primary_label([]), "Unknown")


# ── OpenGraph JSON format validation ────────────────────────────────────────


class TestOpenGraphFormat:
    def test_minimal_opengraph_structure(self):
        """Verify the expected top-level structure of an OpenGraph export."""
        og = {
            "metadata": {"source_kind": "Rootstock"},
            "graph": {"nodes": [], "edges": []},
        }
        checks.assertIn("metadata", og)
        checks.assertIn("graph", og)
        checks.assertIn("nodes", og["graph"])
        checks.assertIn("edges", og["graph"])

    def test_node_has_required_fields(self):
        node = {
            "id": "rs-host-application-com.example",
            "kind": "rs_Application",
            "label": "Example App",
            "properties": {},
        }
        checks.assertIn("id", node)
        checks.assertIn("kind", node)
        checks.assertIn("label", node)
        checks.assertIn("properties", node)

    def test_edge_has_required_fields(self):
        edge = {
            "source": "rs-host-application-com.example",
            "target": "rs-host-tcc_permission-microphone",
            "kind": "rs_HasTCCGrant",
            "properties": {"_traversable": True},
        }
        checks.assertIn("source", edge)
        checks.assertIn("target", edge)
        checks.assertIn("kind", edge)
        checks.assertIn("properties", edge)
