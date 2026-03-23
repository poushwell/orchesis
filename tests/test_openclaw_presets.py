from __future__ import annotations

import copy

import pytest

from orchesis.openclaw_presets import (
    OPENCLAW_DETECTION_PATTERNS,
    PAPERCLIP_PRESET,
    PRESET_NAMES,
    get_named_preset,
    get_openclaw_preset,
    verify_preset,
    verify_preset_dict,
)


def test_openclaw_preset_has_session_header() -> None:
    p = get_openclaw_preset()
    oc = p["openclaw"]
    assert oc["primary_session_header"] == "x-openclaw-session-id"
    assert "x-openclaw-session-id" in oc["session_headers"]
    tt = p.get("task_tracking") or {}
    assert "x-openclaw-session-id" in (tt.get("openclaw_session_headers") or [])


def test_openclaw_preset_has_reset_commands() -> None:
    cmds = get_openclaw_preset()["loop_detection"]["openclaw_reset_commands"]
    assert cmds == ["/start", "/new", "/reset"]


def test_openclaw_preset_exec_loop_pattern() -> None:
    ids = get_openclaw_preset()["openclaw"]["detection_pattern_ids"]
    assert "exec_loop_122" in ids
    assert "exec_loop_122" in OPENCLAW_DETECTION_PATTERNS


def test_paperclip_preset_exists() -> None:
    p = get_named_preset("paperclip")
    assert "paperclip" in p
    assert p["paperclip"]["mcp_scanner"]["check_dangerously_skip_permissions"] is True
    assert PAPERCLIP_PRESET["paperclip"]["mcp_scanner"]["check_adapter_config"] is True


def test_paperclip_preset_has_heartbeat_config() -> None:
    p = get_named_preset("paperclip")
    assert p["model_routing"]["enabled"] is True
    assert "heartbeat_models" in p["model_routing"]
    hb = p["model_routing"]["heartbeat_models"]
    assert hb.get("openai") and hb.get("default")
    assert p["loop_detection"]["content_loop"]["max_identical"] >= 12


def test_verify_preset_catches_invalid() -> None:
    err = verify_preset("not_a_real_preset_name")
    assert err
    assert any("Unknown preset" in m for m in err)

    bad = verify_preset_dict(
        {
            "default_action": "allow",
            "capabilities": [],
            "openclaw": {"detection_pattern_ids": ["__no_such_pattern__"], "session_headers": ["x-openclaw-session-id"]},
        }
    )
    assert any("Unknown detection_pattern_id" in m for m in bad)

    conflict = verify_preset_dict(
        {
            "default_action": "allow",
            "capabilities": [],
            "loop_detection": {"warn_threshold": 9, "block_threshold": 3},
            "openclaw": {"session_headers": ["x-openclaw-session-id"], "detection_pattern_ids": []},
        }
    )
    assert any("warn_threshold" in m and "block_threshold" in m for m in conflict)


def test_all_presets_verify_clean() -> None:
    for name in PRESET_NAMES:
        assert verify_preset(name) == [], f"preset {name!r}: {verify_preset(name)}"


def test_paperclip_preset_includes_paperclip_pattern() -> None:
    ids = get_named_preset("paperclip")["openclaw"]["detection_pattern_ids"]
    assert "paperclip_dangerously_skip_permissions" in ids


def test_unknown_top_level_key_reported() -> None:
    p = copy.deepcopy(get_openclaw_preset())
    p["totally_unknown_section_xyz"] = {"a": 1}
    errs = verify_preset_dict(p)
    assert any("totally_unknown_section_xyz" in m or "Unknown top-level" in m for m in errs)
