"""Flow X-Ray: conversation topology analysis and pattern detection."""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import statistics
import threading
import time
from typing import Any


class NodeType(Enum):
    """Type of node in conversation flow graph."""

    LLM_CALL = "llm_call"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    USER_MESSAGE = "user_message"
    ERROR = "error"


class EdgeType(Enum):
    """Type of edge (transition) between nodes."""

    SEQUENTIAL = "sequential"
    TRIGGERS = "triggers"
    RESPONDS_TO = "responds_to"
    RETRY = "retry"
    ESCALATION = "escalation"


@dataclass
class FlowNode:
    """Single node in the conversation flow graph."""

    node_id: str
    node_type: NodeType
    timestamp: float
    model: str = ""
    tool_name: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    status: str = "ok"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowEdge:
    """Directed edge between two flow nodes."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0


@dataclass
class FlowGraph:
    """Directed graph representing one session's conversation flow."""

    session_id: str
    nodes: dict[str, FlowNode] = field(default_factory=dict)
    edges: list[FlowEdge] = field(default_factory=list)
    start_time: float = 0.0

    def add_node(self, node: FlowNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, edge: FlowEdge) -> None:
        self.edges.append(edge)

    def get_adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            adj[edge.source_id].append(edge.target_id)
        return adj

    def get_node_sequence(self) -> list[FlowNode]:
        return sorted(self.nodes.values(), key=lambda node: node.timestamp)


class PatternType(Enum):
    """Types of detected flow patterns."""

    REDUNDANT_TOOL_CALLS = "redundant_tool_calls"
    EXCESSIVE_RETRIES = "excessive_retries"
    UNNECESSARY_ESCALATION = "unnecessary_escalation"
    CONTEXT_LOSS = "context_loss"
    PING_PONG = "ping_pong"
    TOOL_CHAIN_INJECTION = "tool_chain_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    SEQUENTIAL_BOTTLENECK = "sequential_bottleneck"
    TOKEN_WASTE = "token_waste"
    LATENCY_SPIKE = "latency_spike"
    DEAD_END = "dead_end"


@dataclass
class DetectedPattern:
    """A pattern found in the flow graph."""

    pattern_type: PatternType
    severity: str
    confidence: float
    affected_nodes: list[str]
    description: str
    suggestion: str
    cost_impact_usd: float = 0.0
    time_impact_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowXRayConfig:
    """Configuration for Flow X-Ray analyzer."""

    enabled: bool = False
    max_sessions: int = 1000
    redundancy_window_seconds: float = 30.0
    retry_threshold: int = 3
    ping_pong_min_repetitions: int = 3
    token_waste_stddev_threshold: float = 2.0
    latency_spike_threshold: float = 0.5
    suspicious_tool_chains: list[list[str]] = field(
        default_factory=lambda: [
            ["read_file", "write_file"],
            ["read_file", "http_request"],
            ["read_file", "fetch_url"],
            ["list_directory", "read_file", "write_file"],
            ["search", "read_file", "http_request"],
            ["database_query", "http_request"],
            ["get_secret", "http_request"],
        ]
    )
    enable_security_patterns: bool = True
    enable_efficiency_patterns: bool = True
    enable_performance_patterns: bool = True


@dataclass
class FlowTopology:
    """Topology metrics for a flow graph."""

    depth: int = 0
    width: int = 0
    density: float = 0.0
    tool_diversity: float = 0.0
    model_switches: int = 0
    unique_tools: int = 0
    total_tool_calls: int = 0
    total_llm_calls: int = 0
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    critical_path: list[str] = field(default_factory=list)


@dataclass
class FlowSummary:
    """Human-readable summary of flow analysis."""

    health_score: float
    total_patterns: int
    critical_patterns: int
    estimated_waste_usd: float
    estimated_waste_ms: float
    top_issue: str
    recommendations: list[str]


@dataclass
class FlowAnalysis:
    """Complete analysis result for a session."""

    session_id: str
    timestamp: float
    topology: FlowTopology
    patterns: list[DetectedPattern]
    summary: FlowSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "topology": asdict(self.topology),
            "patterns": [
                {
                    "pattern_type": item.pattern_type.value,
                    "severity": item.severity,
                    "confidence": item.confidence,
                    "affected_nodes": list(item.affected_nodes),
                    "description": item.description,
                    "suggestion": item.suggestion,
                    "cost_impact_usd": item.cost_impact_usd,
                    "time_impact_ms": item.time_impact_ms,
                    "metadata": dict(item.metadata),
                }
                for item in self.patterns
            ],
            "summary": asdict(self.summary),
        }


class FlowAnalyzer:
    """Analyze conversation flow graphs for patterns and topology."""

    def __init__(self, config: FlowXRayConfig | dict[str, Any] | None = None):
        if isinstance(config, FlowXRayConfig):
            self._config = config
        else:
            cfg = config if isinstance(config, dict) else {}
            self._config = FlowXRayConfig(
                enabled=bool(cfg.get("enabled", False)),
                max_sessions=max(1, int(cfg.get("max_sessions", 1000))),
                redundancy_window_seconds=float(cfg.get("redundancy_window_seconds", 30.0)),
                retry_threshold=max(1, int(cfg.get("retry_threshold", 3))),
                ping_pong_min_repetitions=max(2, int(cfg.get("ping_pong_min_repetitions", 3))),
                token_waste_stddev_threshold=max(0.5, float(cfg.get("token_waste_stddev_threshold", 2.0))),
                latency_spike_threshold=max(0.1, min(1.0, float(cfg.get("latency_spike_threshold", 0.5)))),
                suspicious_tool_chains=[
                    [str(tool).strip() for tool in chain if str(tool).strip()]
                    for chain in cfg.get("suspicious_tool_chains", FlowXRayConfig().suspicious_tool_chains)
                    if isinstance(chain, list)
                ],
                enable_security_patterns=bool(cfg.get("enable_security_patterns", True)),
                enable_efficiency_patterns=bool(cfg.get("enable_efficiency_patterns", True)),
                enable_performance_patterns=bool(cfg.get("enable_performance_patterns", True)),
            )
        self._lock = threading.Lock()
        self._session_graphs: OrderedDict[str, FlowGraph] = OrderedDict()
        self._pattern_stats: dict[str, int] = defaultdict(int)
        self._node_counter: int = 0
        self._last_node_by_session: dict[str, str] = {}
        self._recent_llm_hashes: dict[str, deque[tuple[float, str, str]]] = defaultdict(deque)
        self._last_tool_by_session: dict[str, tuple[str, str]] = {}

    def _next_node_id(self) -> str:
        self._node_counter += 1
        return f"n{self._node_counter}"

    def _get_or_create_graph(self, session_id: str, now: float) -> FlowGraph:
        graph = self._session_graphs.get(session_id)
        if graph is None:
            graph = FlowGraph(session_id=session_id, start_time=now)
            self._session_graphs[session_id] = graph
            while len(self._session_graphs) > self._config.max_sessions:
                old_sid, _ = self._session_graphs.popitem(last=False)
                self._last_node_by_session.pop(old_sid, None)
                self._recent_llm_hashes.pop(old_sid, None)
                self._last_tool_by_session.pop(old_sid, None)
        else:
            self._session_graphs.move_to_end(session_id)
        return graph

    @staticmethod
    def _hash_messages(messages: Any) -> str:
        try:
            raw = json.dumps(messages if isinstance(messages, list) else [], ensure_ascii=False, sort_keys=True)
        except Exception:
            raw = ""
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_tool_input(tool_name: str, tool_input: Any) -> str:
        try:
            raw = json.dumps(tool_input if isinstance(tool_input, dict) else tool_input, ensure_ascii=False, sort_keys=True)
        except Exception:
            raw = repr(tool_input)
        return hashlib.sha256(f"{tool_name}:{raw}".encode("utf-8")).hexdigest()

    def record_request(self, session_id: str, model: str, messages: list, tools: list[str] | None = None) -> str:
        now = time.monotonic()
        with self._lock:
            graph = self._get_or_create_graph(session_id, now)
            node_id = self._next_node_id()
            node = FlowNode(
                node_id=node_id,
                node_type=NodeType.LLM_CALL,
                timestamp=now,
                model=str(model or ""),
                metadata={
                    "messages_hash": self._hash_messages(messages),
                    "messages_count": len(messages) if isinstance(messages, list) else 0,
                    "tools": list(tools or []),
                },
            )
            graph.add_node(node)
            last = self._last_node_by_session.get(session_id)
            if isinstance(last, str) and last in graph.nodes:
                graph.add_edge(FlowEdge(source_id=last, target_id=node_id, edge_type=EdgeType.SEQUENTIAL))
            # Retry + escalation hints on sequential llm requests.
            llm_history = self._recent_llm_hashes[session_id]
            while llm_history and (now - llm_history[0][0]) > 300.0:
                llm_history.popleft()
            for prev_ts, prev_node, prev_hash in reversed(llm_history):
                if (now - prev_ts) > 120.0:
                    break
                if prev_hash == node.metadata["messages_hash"]:
                    graph.add_edge(FlowEdge(source_id=prev_node, target_id=node_id, edge_type=EdgeType.RETRY))
                    prev_model = graph.nodes.get(prev_node).model if prev_node in graph.nodes else ""
                    if prev_model and node.model and prev_model != node.model:
                        graph.add_edge(FlowEdge(source_id=prev_node, target_id=node_id, edge_type=EdgeType.ESCALATION))
                    break
            llm_history.append((now, node_id, str(node.metadata["messages_hash"])))
            self._last_node_by_session[session_id] = node_id
            return node_id

    def record_response(
        self,
        session_id: str,
        node_id: str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
        latency_ms: float,
        status: str = "ok",
        tool_calls: list[dict[str, Any]] | None = None,
    ) -> list[str]:
        now = time.monotonic()
        created: list[str] = []
        with self._lock:
            graph = self._get_or_create_graph(session_id, now)
            node = graph.nodes.get(node_id)
            if node is None:
                return created
            node.tokens_in = max(0, int(tokens_in))
            node.tokens_out = max(0, int(tokens_out))
            node.cost_usd = max(0.0, float(cost_usd))
            node.latency_ms = max(0.0, float(latency_ms))
            node.status = str(status or "ok")
            for call in tool_calls or []:
                if not isinstance(call, dict):
                    continue
                tool_name = str(call.get("name", "")).strip()
                if not tool_name:
                    continue
                tool_node_id = self._next_node_id()
                tool_input = call.get("input", {})
                tool_node = FlowNode(
                    node_id=tool_node_id,
                    node_type=NodeType.TOOL_USE,
                    timestamp=now,
                    tool_name=tool_name,
                    status="ok",
                    metadata={
                        "input": tool_input if isinstance(tool_input, dict) else {},
                        "args_hash": self._hash_tool_input(tool_name, tool_input),
                    },
                )
                graph.add_node(tool_node)
                graph.add_edge(FlowEdge(source_id=node_id, target_id=tool_node_id, edge_type=EdgeType.TRIGGERS))
                last = self._last_node_by_session.get(session_id)
                if isinstance(last, str) and last in graph.nodes and last != node_id:
                    graph.add_edge(FlowEdge(source_id=last, target_id=tool_node_id, edge_type=EdgeType.SEQUENTIAL))
                self._last_node_by_session[session_id] = tool_node_id
                self._last_tool_by_session[session_id] = (tool_node_id, tool_name)
                created.append(tool_node_id)
            if not created:
                self._last_node_by_session[session_id] = node_id
            return created

    def record_tool_result(self, session_id: str, tool_node_id: str, result_size: int, status: str = "ok") -> str:
        now = time.monotonic()
        with self._lock:
            graph = self._get_or_create_graph(session_id, now)
            tool_node = graph.nodes.get(tool_node_id)
            if tool_node is None:
                return ""
            node_id = self._next_node_id()
            result_node = FlowNode(
                node_id=node_id,
                node_type=NodeType.TOOL_RESULT,
                timestamp=now,
                tool_name=tool_node.tool_name,
                status=str(status or "ok"),
                metadata={"result_size": max(0, int(result_size))},
            )
            graph.add_node(result_node)
            graph.add_edge(FlowEdge(source_id=tool_node_id, target_id=node_id, edge_type=EdgeType.RESPONDS_TO))
            self._last_node_by_session[session_id] = node_id
            return node_id

    def list_sessions(self) -> list[dict[str, Any]]:
        with self._lock:
            sessions = []
            for sid, graph in self._session_graphs.items():
                sessions.append(
                    {
                        "id": sid,
                        "node_count": len(graph.nodes),
                        "edge_count": len(graph.edges),
                        "start_time": graph.start_time,
                    }
                )
            return sorted(sessions, key=lambda item: float(item.get("start_time", 0.0)), reverse=True)

    def get_session_graph(self, session_id: str) -> FlowGraph | None:
        with self._lock:
            graph = self._session_graphs.get(session_id)
            return None if graph is None else FlowGraph(
                session_id=graph.session_id,
                nodes=dict(graph.nodes),
                edges=list(graph.edges),
                start_time=graph.start_time,
            )

    def export_graph_json(self, session_id: str) -> str:
        graph = self.get_session_graph(session_id)
        if graph is None:
            return ""
        payload = {
            "session_id": graph.session_id,
            "start_time": graph.start_time,
            "nodes": [
                {
                    "node_id": node.node_id,
                    "node_type": node.node_type.value,
                    "timestamp": node.timestamp,
                    "model": node.model,
                    "tool_name": node.tool_name,
                    "tokens_in": node.tokens_in,
                    "tokens_out": node.tokens_out,
                    "cost_usd": node.cost_usd,
                    "latency_ms": node.latency_ms,
                    "status": node.status,
                    "metadata": node.metadata,
                }
                for node in graph.get_node_sequence()
            ],
            "edges": [
                {
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "edge_type": edge.edge_type.value,
                    "weight": edge.weight,
                }
                for edge in graph.edges
            ],
        }
        return json.dumps(payload, ensure_ascii=False)

    def _detect_redundant_tools(self, graph: FlowGraph) -> list[DetectedPattern]:
        out: list[DetectedPattern] = []
        by_tool_hash: dict[tuple[str, str], list[FlowNode]] = defaultdict(list)
        tools = [n for n in graph.nodes.values() if n.node_type == NodeType.TOOL_USE]
        for node in tools:
            args_hash = str(node.metadata.get("args_hash", ""))
            by_tool_hash[(node.tool_name, args_hash)].append(node)
        for (tool_name, _), nodes in by_tool_hash.items():
            if len(nodes) > 1:
                affected = [n.node_id for n in sorted(nodes, key=lambda x: x.timestamp)]
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.REDUNDANT_TOOL_CALLS,
                        severity="medium" if len(nodes) < 4 else "high",
                        confidence=min(1.0, 0.55 + (len(nodes) - 1) * 0.15),
                        affected_nodes=affected,
                        description=f"Tool '{tool_name}' called redundantly with identical arguments.",
                        suggestion="Cache tool responses or deduplicate repeated calls.",
                        cost_impact_usd=0.0,
                    )
                )
        # Fuzzy redundancy by short interval same tool.
        by_tool: dict[str, list[FlowNode]] = defaultdict(list)
        for node in tools:
            by_tool[node.tool_name].append(node)
        for tool_name, nodes in by_tool.items():
            ordered = sorted(nodes, key=lambda x: x.timestamp)
            streak: list[str] = []
            for item in ordered:
                if not streak:
                    streak.append(item.node_id)
                    continue
                prev = graph.nodes[streak[-1]]
                if (item.timestamp - prev.timestamp) <= self._config.redundancy_window_seconds:
                    streak.append(item.node_id)
                else:
                    if len(streak) >= 3:
                        out.append(
                            DetectedPattern(
                                pattern_type=PatternType.REDUNDANT_TOOL_CALLS,
                                severity="medium",
                                confidence=0.65,
                                affected_nodes=list(streak),
                                description=f"Tool '{tool_name}' repeatedly called in short window.",
                                suggestion="Batch or debounce repeated tool calls.",
                            )
                        )
                    streak = [item.node_id]
            if len(streak) >= 3:
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.REDUNDANT_TOOL_CALLS,
                        severity="medium",
                        confidence=0.65,
                        affected_nodes=list(streak),
                        description=f"Tool '{tool_name}' repeatedly called in short window.",
                        suggestion="Batch or debounce repeated tool calls.",
                    )
                )
        return out

    def _detect_ping_pong(self, graph: FlowGraph) -> list[DetectedPattern]:
        tools = [n for n in graph.get_node_sequence() if n.node_type == NodeType.TOOL_USE]
        if len(tools) < 4:
            return []
        names = [n.tool_name for n in tools]
        out: list[DetectedPattern] = []
        best_seq: list[str] = []
        for i in range(len(names) - 3):
            a, b = names[i], names[i + 1]
            if not a or not b or a == b:
                continue
            j = i
            seq: list[str] = []
            while j < len(names):
                expected = a if (j - i) % 2 == 0 else b
                if names[j] != expected:
                    break
                seq.append(tools[j].node_id)
                j += 1
            repetitions = len(seq) // 2
            if repetitions >= self._config.ping_pong_min_repetitions and len(seq) > len(best_seq):
                best_seq = seq
        if best_seq:
            out.append(
                DetectedPattern(
                    pattern_type=PatternType.PING_PONG,
                    severity="high" if len(best_seq) >= 8 else "medium",
                    confidence=min(1.0, 0.6 + len(best_seq) * 0.04),
                    affected_nodes=best_seq,
                    description="Detected ping-pong behavior between tools.",
                    suggestion="Consolidate tool logic or add stopping criteria.",
                )
            )
        return out

    def _detect_context_loss(self, graph: FlowGraph) -> list[DetectedPattern]:
        out: list[DetectedPattern] = []
        seen: dict[tuple[str, str], float] = {}
        for node in graph.get_node_sequence():
            if node.node_type != NodeType.TOOL_USE:
                continue
            key = (node.tool_name, str(node.metadata.get("args_hash", "")))
            if key in seen and (node.timestamp - seen[key]) > self._config.redundancy_window_seconds:
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.CONTEXT_LOSS,
                        severity="medium",
                        confidence=0.7,
                        affected_nodes=[node.node_id],
                        description=f"Tool '{node.tool_name}' repeated after unrelated steps.",
                        suggestion="Persist intermediate state to avoid repeating completed work.",
                    )
                )
            seen[key] = node.timestamp
        return out

    def _detect_excessive_retries(self, graph: FlowGraph) -> list[DetectedPattern]:
        out: list[DetectedPattern] = []
        seq = graph.get_node_sequence()
        i = 0
        while i < len(seq):
            node = seq[i]
            if node.node_type != NodeType.LLM_CALL or node.status not in {"error", "timeout"}:
                i += 1
                continue
            j = i + 1
            group = [node.node_id]
            while j < len(seq):
                nxt = seq[j]
                if nxt.node_type == NodeType.LLM_CALL and nxt.model == node.model and nxt.status in {"error", "timeout"}:
                    group.append(nxt.node_id)
                    j += 1
                    continue
                break
            if len(group) > self._config.retry_threshold:
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.EXCESSIVE_RETRIES,
                        severity="high",
                        confidence=min(1.0, 0.6 + len(group) * 0.08),
                        affected_nodes=group,
                        description=f"Detected {len(group)} consecutive retries for model '{node.model}'.",
                        suggestion="Introduce exponential backoff and fallback model.",
                    )
                )
            i = j
        return out

    def _detect_tool_chain_injection(self, graph: FlowGraph) -> list[DetectedPattern]:
        if not self._config.enable_security_patterns:
            return []
        tools = [n for n in graph.get_node_sequence() if n.node_type == NodeType.TOOL_USE]
        names = [n.tool_name for n in tools]
        out: list[DetectedPattern] = []
        for chain in self._config.suspicious_tool_chains:
            if not chain:
                continue
            chain_len = len(chain)
            for i in range(0, len(names) - chain_len + 1):
                if names[i : i + chain_len] == chain:
                    affected = [tools[i + k].node_id for k in range(chain_len)]
                    out.append(
                        DetectedPattern(
                            pattern_type=PatternType.TOOL_CHAIN_INJECTION,
                            severity="critical" if chain_len >= 3 else "high",
                            confidence=min(1.0, 0.7 + chain_len * 0.08),
                            affected_nodes=affected,
                            description=f"Suspicious tool chain detected: {' -> '.join(chain)}",
                            suggestion="Add policy guardrails for chained tool execution.",
                        )
                    )
        return out

    def _detect_token_waste(self, graph: FlowGraph) -> list[DetectedPattern]:
        llm_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.LLM_CALL]
        if len(llm_nodes) < 3:
            return []
        values = [max(0, int(node.tokens_in)) for node in llm_nodes]
        try:
            avg = statistics.mean(values)
            std = statistics.pstdev(values)
        except statistics.StatisticsError:
            return []
        median = statistics.median(values)
        threshold = min(avg + std * self._config.token_waste_stddev_threshold, median * 5.0)
        out: list[DetectedPattern] = []
        for node in llm_nodes:
            if float(node.tokens_in) > threshold and node.tokens_out <= max(1, node.tokens_in // 20):
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.TOKEN_WASTE,
                        severity="medium",
                        confidence=0.75,
                        affected_nodes=[node.node_id],
                        description="High input token spend with low output utility.",
                        suggestion="Trim context window and use retrieval/caching.",
                        cost_impact_usd=max(0.0, node.cost_usd * 0.5),
                    )
                )
        return out

    def _detect_sequential_bottleneck(self, graph: FlowGraph) -> list[DetectedPattern]:
        tools = [n for n in graph.get_node_sequence() if n.node_type == NodeType.TOOL_USE]
        if len(tools) < 3:
            return []
        run: list[FlowNode] = []
        out: list[DetectedPattern] = []
        for node in tools:
            if not run:
                run = [node]
                continue
            prev = run[-1]
            if (node.timestamp - prev.timestamp) <= self._config.redundancy_window_seconds and node.tool_name != prev.tool_name:
                run.append(node)
            else:
                if len(run) >= 3:
                    out.append(
                        DetectedPattern(
                            pattern_type=PatternType.SEQUENTIAL_BOTTLENECK,
                            severity="medium",
                            confidence=0.65,
                            affected_nodes=[item.node_id for item in run],
                            description="Independent tools called sequentially in short window.",
                            suggestion="Parallelize tool calls where data dependencies are absent.",
                            time_impact_ms=sum(float(item.latency_ms) for item in run) * 0.4,
                        )
                    )
                run = [node]
        if len(run) >= 3:
            out.append(
                DetectedPattern(
                    pattern_type=PatternType.SEQUENTIAL_BOTTLENECK,
                    severity="medium",
                    confidence=0.65,
                    affected_nodes=[item.node_id for item in run],
                    description="Independent tools called sequentially in short window.",
                    suggestion="Parallelize tool calls where data dependencies are absent.",
                    time_impact_ms=sum(float(item.latency_ms) for item in run) * 0.4,
                )
            )
        return out

    def _detect_dead_ends(self, graph: FlowGraph) -> list[DetectedPattern]:
        ordered = graph.get_node_sequence()
        positions = {node.node_id: idx for idx, node in enumerate(ordered)}
        llm_by_time = [n for n in ordered if n.node_type == NodeType.LLM_CALL]
        result_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.TOOL_RESULT]
        out: list[DetectedPattern] = []
        for res in result_nodes:
            used = False
            res_pos = positions.get(res.node_id, -1)
            for llm in llm_by_time:
                if positions.get(llm.node_id, -1) <= res_pos:
                    continue
                # Conservative heuristic: any subsequent LLM call likely consumes prior tool result.
                used = True
                refs = llm.metadata.get("tool_result_refs", [])
                if isinstance(refs, list) and res.node_id in refs:
                    used = True
                    break
                break
            if not used:
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.DEAD_END,
                        severity="low",
                        confidence=0.7,
                        affected_nodes=[res.node_id],
                        description="Tool result produced but not referenced by subsequent LLM calls.",
                        suggestion="Avoid unnecessary tool calls or wire result back into prompt.",
                    )
                )
        return out

    def _detect_latency_spikes(self, graph: FlowGraph) -> list[DetectedPattern]:
        nodes = [n for n in graph.nodes.values() if n.latency_ms > 0]
        total_latency = sum(float(n.latency_ms) for n in nodes)
        if total_latency <= 0:
            return []
        out: list[DetectedPattern] = []
        for node in nodes:
            ratio = float(node.latency_ms) / total_latency
            if ratio >= self._config.latency_spike_threshold:
                out.append(
                    DetectedPattern(
                        pattern_type=PatternType.LATENCY_SPIKE,
                        severity="high" if ratio >= 0.7 else "medium",
                        confidence=min(1.0, 0.6 + ratio),
                        affected_nodes=[node.node_id],
                        description="Single node dominates overall latency.",
                        suggestion="Consider cache responses, timeout tuning, or model downgrade.",
                        time_impact_ms=float(node.latency_ms) * 0.5,
                    )
                )
        return out

    def _compute_topology(self, graph: FlowGraph) -> FlowTopology:
        seq = graph.get_node_sequence()
        node_count = len(seq)
        if node_count == 0:
            return FlowTopology()
        adj = graph.get_adjacency()
        in_degree: dict[str, int] = defaultdict(int)
        for edge in graph.edges:
            in_degree[edge.target_id] += 1
        queue = deque([node.node_id for node in seq if in_degree[node.node_id] == 0])
        depth_by_node: dict[str, int] = {item: 1 for item in queue}
        while queue:
            current = queue.popleft()
            for target in adj.get(current, []):
                depth_by_node[target] = max(depth_by_node.get(target, 1), depth_by_node.get(current, 1) + 1)
                in_degree[target] -= 1
                if in_degree[target] == 0:
                    queue.append(target)
        depth = max(depth_by_node.values()) if depth_by_node else 1
        width_by_depth: dict[int, int] = defaultdict(int)
        for d in depth_by_node.values():
            width_by_depth[d] += 1
        width = max(width_by_depth.values()) if width_by_depth else 1
        density = 0.0
        if node_count > 1:
            density = len(graph.edges) / float(node_count * (node_count - 1))
        tools = [n.tool_name for n in seq if n.node_type == NodeType.TOOL_USE and n.tool_name]
        unique_tools = len(set(tools))
        total_tool_calls = len(tools)
        llm = [n for n in seq if n.node_type == NodeType.LLM_CALL]
        models = [n.model for n in llm if n.model]
        model_switches = 0
        for i in range(1, len(models)):
            if models[i] != models[i - 1]:
                model_switches += 1
        total_cost = sum(float(n.cost_usd) for n in seq)
        total_tokens = sum(int(n.tokens_in) + int(n.tokens_out) for n in seq)
        total_latency = sum(float(n.latency_ms) for n in seq)
        critical_path = [n.node_id for n in sorted(seq, key=lambda n: float(n.latency_ms), reverse=True)[: min(5, len(seq))]]
        return FlowTopology(
            depth=int(depth),
            width=int(width),
            density=round(density, 6),
            tool_diversity=round((unique_tools / total_tool_calls) if total_tool_calls > 0 else 0.0, 6),
            model_switches=model_switches,
            unique_tools=unique_tools,
            total_tool_calls=total_tool_calls,
            total_llm_calls=len(llm),
            total_cost_usd=round(total_cost, 8),
            total_tokens=total_tokens,
            total_latency_ms=round(total_latency, 6),
            critical_path=critical_path,
        )

    @staticmethod
    def _build_summary(patterns: list[DetectedPattern]) -> FlowSummary:
        severity_penalty = {"critical": 0.30, "high": 0.18, "medium": 0.09, "low": 0.04, "info": 0.01}
        health = 1.0
        for item in patterns:
            health -= severity_penalty.get(item.severity, 0.05) * max(0.2, min(1.0, item.confidence))
        health = max(0.0, min(1.0, health))
        critical = sum(1 for item in patterns if item.severity == "critical")
        waste_usd = round(sum(max(0.0, float(item.cost_impact_usd)) for item in patterns), 8)
        waste_ms = round(sum(max(0.0, float(item.time_impact_ms)) for item in patterns), 6)
        top_issue = patterns[0].description if patterns else "No significant issues detected."
        recommendations: list[str] = []
        for item in patterns:
            if item.suggestion not in recommendations:
                recommendations.append(item.suggestion)
            if len(recommendations) >= 3:
                break
        return FlowSummary(
            health_score=round(health, 6),
            total_patterns=len(patterns),
            critical_patterns=critical,
            estimated_waste_usd=waste_usd,
            estimated_waste_ms=waste_ms,
            top_issue=top_issue,
            recommendations=recommendations,
        )

    def analyze_session(self, session_id: str) -> FlowAnalysis | None:
        graph = self.get_session_graph(session_id)
        if graph is None:
            return None
        patterns: list[DetectedPattern] = []
        if self._config.enable_efficiency_patterns:
            patterns.extend(self._detect_redundant_tools(graph))
            patterns.extend(self._detect_ping_pong(graph))
            patterns.extend(self._detect_context_loss(graph))
            patterns.extend(self._detect_excessive_retries(graph))
            patterns.extend(self._detect_dead_ends(graph))
        if self._config.enable_security_patterns:
            patterns.extend(self._detect_tool_chain_injection(graph))
        if self._config.enable_performance_patterns:
            patterns.extend(self._detect_token_waste(graph))
            patterns.extend(self._detect_sequential_bottleneck(graph))
            patterns.extend(self._detect_latency_spikes(graph))
        patterns.sort(key=lambda p: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(p.severity, 9), -p.confidence))
        topology = self._compute_topology(graph)
        summary = self._build_summary(patterns)
        with self._lock:
            for item in patterns:
                self._pattern_stats[item.pattern_type.value] += 1
        return FlowAnalysis(
            session_id=session_id,
            timestamp=time.time(),
            topology=topology,
            patterns=patterns,
            summary=summary,
        )

    def analyze_from_recording(self, recording: list[dict[str, Any]]) -> FlowAnalysis:
        sid = "recording"
        if recording and isinstance(recording[0], dict):
            sid = str(recording[0].get("session_id", "recording")) or "recording"
        with self._lock:
            self._session_graphs.pop(sid, None)
            self._last_node_by_session.pop(sid, None)
            self._recent_llm_hashes.pop(sid, None)
        for entry in recording:
            if not isinstance(entry, dict):
                continue
            req = entry.get("request")
            if not isinstance(req, dict):
                req = {}
            model = str(entry.get("model", req.get("model", "")))
            messages = req.get("messages", [])
            tools = req.get("tools", [])
            tool_names: list[str] = []
            if isinstance(tools, list):
                for item in tools:
                    if isinstance(item, dict):
                        name = item.get("name")
                        if isinstance(name, str) and name:
                            tool_names.append(name)
                    elif isinstance(item, str) and item:
                        tool_names.append(item)
            node_id = self.record_request(sid, model=model, messages=messages if isinstance(messages, list) else [], tools=tool_names)
            resp = entry.get("response")
            usage = {}
            if isinstance(resp, dict):
                usage_raw = resp.get("usage")
                usage = usage_raw if isinstance(usage_raw, dict) else {}
            tokens_in = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
            tokens_out = int(usage.get("completion_tokens") or usage.get("output_tokens") or 0)
            tool_calls: list[dict[str, Any]] = []
            if isinstance(resp, dict):
                content = resp.get("content")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            tool_calls.append({"name": str(block.get("name", "")), "input": block.get("input", {})})
                choices = resp.get("choices")
                if isinstance(choices, list):
                    for choice in choices:
                        if not isinstance(choice, dict):
                            continue
                        msg = choice.get("message")
                        if not isinstance(msg, dict):
                            continue
                        tcs = msg.get("tool_calls")
                        if not isinstance(tcs, list):
                            continue
                        for tc in tcs:
                            if not isinstance(tc, dict):
                                continue
                            fn = tc.get("function")
                            if not isinstance(fn, dict):
                                continue
                            name = str(fn.get("name", ""))
                            raw_args = fn.get("arguments", {})
                            args = {}
                            if isinstance(raw_args, dict):
                                args = raw_args
                            elif isinstance(raw_args, str):
                                try:
                                    parsed = json.loads(raw_args)
                                    if isinstance(parsed, dict):
                                        args = parsed
                                except Exception:
                                    args = {}
                            tool_calls.append({"name": name, "input": args})
            status = "ok" if int(entry.get("status_code", 200) or 200) < 400 else "error"
            self.record_response(
                sid,
                node_id=node_id,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=float(entry.get("cost", 0.0) or 0.0),
                latency_ms=float(entry.get("latency_ms", 0.0) or 0.0),
                status=status,
                tool_calls=tool_calls,
            )
        analysis = self.analyze_session(sid)
        if analysis is None:
            return FlowAnalysis(
                session_id=sid,
                timestamp=time.time(),
                topology=FlowTopology(),
                patterns=[],
                summary=self._build_summary([]),
            )
        return analysis

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessions_tracked": len(self._session_graphs),
                "pattern_counts": dict(self._pattern_stats),
                "max_sessions": self._config.max_sessions,
            }
