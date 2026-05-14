"""Tests for OrchesisHookRegistry and OrchesisPlugin (extension foundation)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from orchesis.plugin_system import (
    OrchesisHookRegistry,
    OrchesisPipelinePluginRegistry,
    OrchesisPlugin,
    PluginInfo,
)


class _EchoPlugin(OrchesisPlugin):
    def __init__(self) -> None:
        self._info = PluginInfo(
            name="echo",
            version="1.0.0",
            hooks=["on_request", "on_response"],
        )

    @property
    def info(self) -> PluginInfo:
        return self._info

    def on_request(self, request: dict, context: dict) -> dict | None:
        out = dict(request)
        out["x"] = 1
        return out

    def on_response(self, response: dict, context: dict) -> dict | None:
        out = dict(response)
        out["y"] = 2
        return out


class _SuppressFindingPlugin(OrchesisPlugin):
    def __init__(self) -> None:
        self._info = PluginInfo(name="suppress", version="0.1.0", hooks=["on_finding"])

    @property
    def info(self) -> PluginInfo:
        return self._info

    def on_finding(self, finding: dict) -> dict | None:
        if finding.get("drop"):
            return None
        return finding


def test_plugin_register_and_list() -> None:
    reg = OrchesisHookRegistry()
    reg.register(_EchoPlugin())
    infos = reg.get_plugins()
    assert len(infos) == 1
    assert infos[0].name == "echo"


def test_plugin_fire_request_hook() -> None:
    reg = OrchesisHookRegistry()
    reg.register(_EchoPlugin())
    out = reg.fire_hook("on_request", request={"a": 1}, context={})
    assert out == [{"a": 1, "x": 1}]


def test_plugin_fire_response_hook() -> None:
    reg = OrchesisHookRegistry()
    reg.register(_EchoPlugin())
    out = reg.fire_hook("on_response", response={"b": 2}, context={})
    assert out == [{"b": 2, "y": 2}]


def test_plugin_finding_suppression() -> None:
    reg = OrchesisHookRegistry()
    reg.register(_SuppressFindingPlugin())
    kept = reg.fire_hook("on_finding", finding={"id": 1})
    assert kept == [{"id": 1}]
    dropped = reg.fire_hook("on_finding", finding={"id": 2, "drop": True})
    assert dropped == [None]


def test_plugin_load_from_path(tmp_path: Path) -> None:
    plugin_file = tmp_path / "sample_plugin.py"
    plugin_file.write_text(
        textwrap.dedent(
            """
            from orchesis.plugin_system import OrchesisPlugin, PluginInfo

            class FilePlugin(OrchesisPlugin):
                def __init__(self):
                    self._i = PluginInfo(name="from_file", version="1.0.0", hooks=["on_startup"])

                @property
                def info(self):
                    return self._i

                def on_startup(self) -> None:
                    self.ran = True
            """
        ),
        encoding="utf-8",
    )
    reg = OrchesisHookRegistry()
    reg.load_from_path(str(plugin_file))
    assert any(p.name == "from_file" for p in reg.get_plugins())


def test_plugin_registry_empty_hooks_safe() -> None:
    reg = OrchesisHookRegistry()
    assert reg.fire_hook("on_request", request={}, context={}) == []
    assert reg.fire_hook("unknown_hook", foo=1) == []


def test_pipeline_registry_alias_matches_hook_registry() -> None:
    reg = OrchesisPipelinePluginRegistry()
    reg.register(_EchoPlugin())
    assert len(reg.get_plugins()) == 1


def test_plugin_load_from_policy(tmp_path: Path) -> None:
    plugin_file = tmp_path / "policy_plugin.py"
    plugin_file.write_text(
        textwrap.dedent(
            """
            from orchesis.plugin_system import OrchesisPlugin, PluginInfo

            class PolicyPathPlugin(OrchesisPlugin):
                def __init__(self):
                    self._i = PluginInfo(
                        name="policy_path",
                        version="1.0.0",
                        author="test",
                        description="from policy",
                        hooks=["on_shutdown"],
                    )

                @property
                def info(self):
                    return self._i

                def on_shutdown(self) -> None:
                    pass
            """
        ),
        encoding="utf-8",
    )
    reg = OrchesisHookRegistry()
    reg.load_from_policy({"plugins": [str(plugin_file)]})
    assert any(p.name == "policy_path" for p in reg.get_plugins())


def test_plugin_register_replaces_same_name() -> None:
    class _A(OrchesisPlugin):
        def __init__(self) -> None:
            self._i = PluginInfo(name="dup", version="1.0.0", hooks=["on_request"])

        @property
        def info(self) -> PluginInfo:
            return self._i

        def on_request(self, request: dict, context: dict) -> dict | None:
            return {**request, "which": "a"}

    class _B(OrchesisPlugin):
        def __init__(self) -> None:
            self._i = PluginInfo(name="dup", version="2.0.0", hooks=["on_request"])

        @property
        def info(self) -> PluginInfo:
            return self._i

        def on_request(self, request: dict, context: dict) -> dict | None:
            return {**request, "which": "b"}

    reg = OrchesisHookRegistry()
    reg.register(_A())
    reg.register(_B())
    out = reg.fire_hook("on_request", request={}, context={})
    assert out == [{"which": "b"}]


def test_plugin_unregister_removes_hooks() -> None:
    reg = OrchesisHookRegistry()
    reg.register(_EchoPlugin())
    reg.unregister("echo")
    assert reg.fire_hook("on_request", request={}, context={}) == []
