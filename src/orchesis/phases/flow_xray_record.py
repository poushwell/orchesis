"""Flow recording phase.

Records a per-request node into the flow analyzer. This is read-only with
respect to `ctx.processed` — the only side effect is the recording handle
emission and the flow analyzer call. The recorded node id is exposed on
`ctx.processed.params` under the key `flow_node_id` for downstream phases
that want to correlate.

Migration note (Checkpoint 1): the legacy `_phase_flow_xray_record` in
proxy.py operates on a different `_RequestContext` shape. This plugin
operates on the new `RequestContext` defined in `orchesis.pipeline.context`
and accepts the `FlowAnalyzer` via constructor injection. The proxy.py
wiring that bridges the legacy context to this phase lands in
Checkpoint 2 (hybrid path).
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from orchesis.pipeline import (
    Phase,
    PhaseResult,
    RequestContext,
)


class FlowAnalyzerLike(Protocol):
    """Minimal interface the phase needs from a flow analyzer."""

    def record_request(
        self,
        *,
        session_id: str,
        model: str,
        messages: list[Mapping[str, Any]],
        tools: list[str],
    ) -> str: ...


class FlowXrayRecordPhase(Phase):
    """Record request entry into the flow analyzer."""

    name = "flow_xray_record"
    version = "0.1.0"
    appends_tracking = frozenset({"metrics"})
    timeout_seconds = 1.0

    def __init__(self, analyzer: FlowAnalyzerLike | None) -> None:
        self._analyzer = analyzer

    async def execute(self, ctx: RequestContext) -> PhaseResult:
        if self._analyzer is None:
            return PhaseResult(status="skip", reason="flow analyzer disabled")

        session_id = ctx.id.session_id or "default"
        model = ctx.processed.model or ctx.input.requested_model

        # Tool names — accept either the canonical {"name": "...", ...} shape
        # or a list of bare strings.
        tool_names: list[str] = []
        for item in (ctx.processed.tools or list(ctx.input.original_tools)):
            if isinstance(item, Mapping):
                name = item.get("name")
                if isinstance(name, str) and name:
                    tool_names.append(name)
            elif isinstance(item, str) and item:
                tool_names.append(item)

        messages_for_analyzer: list[Mapping[str, Any]] = (
            ctx.processed.messages
            if ctx.processed.messages
            else list(ctx.input.original_messages)
        )

        flow_node_id = self._analyzer.record_request(
            session_id=session_id,
            model=model,
            messages=messages_for_analyzer,
            tools=tool_names,
        )

        # Park the node id in processed params for downstream phases. We
        # avoid mutating ctx.processed.params keys outside our declared set;
        # this is a known limitation tightened in CP3 once writes_processed
        # is enforced strictly.
        ctx.processed.params["flow_node_id"] = flow_node_id

        # CP2 hybrid path: when a legacy `_RequestContext` is parked in
        # params, sync flow_node_id back so hardcoded phases that read
        # `legacy_ctx.flow_node_id` continue to work unchanged.
        legacy_ctx = ctx.processed.params.get("_legacy_ctx")
        if legacy_ctx is not None:
            try:
                legacy_ctx.flow_node_id = flow_node_id
            except AttributeError:
                pass

        return PhaseResult(
            status="pass",
            details={"flow_node_id": flow_node_id},
        )
