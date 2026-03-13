"""OpenAI tool call/result message-chain validation and repair helpers."""

from __future__ import annotations

from typing import Any

from orchesis.input_guard import sanitize_text


def _copy_message(msg: dict[str, Any]) -> dict[str, Any]:
    copied = dict(msg)
    if isinstance(msg.get("tool_calls"), list):
        copied["tool_calls"] = [dict(tc) if isinstance(tc, dict) else tc for tc in msg["tool_calls"]]
    return copied


def _has_text_content(message: dict[str, Any]) -> bool:
    content = message.get("content")
    if isinstance(content, str):
        safe = sanitize_text(content)
        return bool(safe and safe.strip())
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                text = block.get("text", block.get("content", ""))
                safe = sanitize_text(text)
                if isinstance(safe, str) and safe.strip():
                    return True
    return False


def extract_tool_call_ids(message: dict) -> set[str]:
    """Extract tool_call_ids from an assistant message with tool_calls."""

    if not isinstance(message, dict):
        return set()
    if str(message.get("role", "")).strip().lower() != "assistant":
        return set()
    tool_calls = message.get("tool_calls", [])
    if not isinstance(tool_calls, list):
        return set()
    result: set[str] = set()
    for item in tool_calls:
        if isinstance(item, dict):
            raw = item.get("id", "")
            if isinstance(raw, str) and raw.strip():
                result.add(raw.strip())
    return result


def extract_tool_result_id(message: dict) -> str:
    """Extract tool_call_id from a tool result message."""

    if not isinstance(message, dict):
        return ""
    if str(message.get("role", "")).strip().lower() != "tool":
        return ""
    raw = message.get("tool_call_id", "")
    if isinstance(raw, str):
        return raw.strip()
    return ""


def find_tool_chain_groups(messages: list[dict]) -> list[dict]:
    """Group messages into tool-chain groups."""

    safe_messages = [m for m in messages if isinstance(m, dict)]
    groups: list[dict[str, Any]] = []
    pending_by_id: dict[str, list[int]] = {}
    assigned_tool_idxs: set[int] = set()
    tool_result_indexes: list[int] = []

    for idx, msg in enumerate(safe_messages):
        call_ids = extract_tool_call_ids(msg)
        if call_ids:
            group = {
                "assistant_idx": idx,
                "tool_call_ids": set(call_ids),
                "tool_result_idxs": [],
                "missing_ids": set(call_ids),
                "orphan_results": [],
                "is_valid": False,
            }
            gidx = len(groups)
            groups.append(group)
            for cid in call_ids:
                pending_by_id.setdefault(cid, []).append(gidx)

        tool_id = extract_tool_result_id(msg)
        if tool_id:
            tool_result_indexes.append(idx)
            pending = pending_by_id.get(tool_id, [])
            if pending:
                assigned_group_idx = pending.pop(0)
                assigned_group = groups[assigned_group_idx]
                assigned_group["tool_result_idxs"].append(idx)
                assigned_group["missing_ids"].discard(tool_id)
                assigned_tool_idxs.add(idx)

    orphan_indexes = [idx for idx in tool_result_indexes if idx not in assigned_tool_idxs]

    for group in groups:
        tool_idxs = sorted(group["tool_result_idxs"])
        call_ids = set(group["tool_call_ids"])
        found_ids: set[str] = set()
        for i in tool_idxs:
            rid = extract_tool_result_id(safe_messages[i])
            if rid:
                found_ids.add(rid)
        group["missing_ids"] = call_ids - found_ids
        group["orphan_results"] = orphan_indexes

        if tool_idxs and not group["missing_ids"]:
            start = int(group["assistant_idx"]) + 1
            end = start + len(call_ids)
            expected = list(range(start, end))
            contiguous = tool_idxs == expected
            all_tools = all(
                str(safe_messages[i].get("role", "")).strip().lower() == "tool" for i in tool_idxs
            )
            group["is_valid"] = bool(contiguous and all_tools and len(found_ids) == len(call_ids))
        else:
            group["is_valid"] = False
    return groups


def handle_failed_tool_chain(messages: list[dict]) -> list[dict]:
    """Strip abandoned tool_calls when no result appears within 5 messages."""

    safe = [_copy_message(m) for m in messages if isinstance(m, dict)]
    result: list[dict[str, Any]] = []
    n = len(safe)
    for idx, msg in enumerate(safe):
        call_ids = extract_tool_call_ids(msg)
        if not call_ids:
            result.append(msg)
            continue
        future = safe[idx + 1 : min(n, idx + 6)]
        future_result_ids = {extract_tool_result_id(item) for item in future if extract_tool_result_id(item)}
        if call_ids & future_result_ids:
            result.append(msg)
            continue
        # Abandoned chain: strip tool calls but keep textual assistant content.
        if _has_text_content(msg):
            cleaned = dict(msg)
            cleaned.pop("tool_calls", None)
            result.append(cleaned)
        # else: drop whole assistant tool-call-only message.
    return result


def validate_tool_chain(messages: list[dict]) -> list[dict]:
    """Validate and repair OpenAI tool-call ordering."""

    base = handle_failed_tool_chain(messages)
    sanitized: list[dict[str, Any]] = []
    for msg in base:
        copied = _copy_message(msg)
        if (
            str(copied.get("role", "")).strip().lower() == "assistant"
            and isinstance(copied.get("tool_calls"), list)
            and len(copied.get("tool_calls", [])) > 0
            and not extract_tool_call_ids(copied)
        ):
            copied.pop("tool_calls", None)
        sanitized.append(copied)
    base = sanitized
    groups = find_tool_chain_groups(base)
    if not groups:
        # Still remove orphan tool results if there are no valid assistant calls.
        return [m for m in base if extract_tool_result_id(m) == ""]

    # Build lookup for tool message ownership.
    tool_to_group: dict[int, int] = {}
    assistant_meta: dict[int, dict[str, Any]] = {}
    orphan_tool_indexes: set[int] = set()
    for gidx, group in enumerate(groups):
        assistant_meta[int(group["assistant_idx"])] = group
        for tidx in group["tool_result_idxs"]:
            tool_to_group[int(tidx)] = gidx
        for oidx in group.get("orphan_results", []):
            orphan_tool_indexes.add(int(oidx))

    output: list[dict[str, Any]] = []
    emitted_tools: set[int] = set()

    for idx, msg in enumerate(base):
        if idx in orphan_tool_indexes:
            continue
        if extract_tool_result_id(msg):
            # tool results are emitted immediately after their assistant group.
            continue

        group = assistant_meta.get(idx)
        if group is None:
            output.append(_copy_message(msg))
            continue

        call_ids = set(group["tool_call_ids"])
        tool_idxs = sorted(int(i) for i in group["tool_result_idxs"])
        found_ids = {
            extract_tool_result_id(base[tidx]) for tidx in tool_idxs if extract_tool_result_id(base[tidx])
        }
        keep_ids = call_ids & found_ids

        if not keep_ids:
            # No matching results: keep text-only assistant or drop.
            if _has_text_content(msg):
                cleaned = _copy_message(msg)
                cleaned.pop("tool_calls", None)
                output.append(cleaned)
            continue

        # Keep only tool calls that have results.
        assistant = _copy_message(msg)
        tool_calls = assistant.get("tool_calls", [])
        if isinstance(tool_calls, list):
            filtered = []
            for call in tool_calls:
                if isinstance(call, dict) and str(call.get("id", "")).strip() in keep_ids:
                    filtered.append(dict(call))
            if filtered:
                assistant["tool_calls"] = filtered
            else:
                assistant.pop("tool_calls", None)
        output.append(assistant)

        # Emit tool results immediately after assistant, preserving original relative order.
        for tidx in tool_idxs:
            if tidx in emitted_tools:
                continue
            tmsg = base[tidx]
            rid = extract_tool_result_id(tmsg)
            if rid and rid in keep_ids:
                output.append(_copy_message(tmsg))
                emitted_tools.add(tidx)

    return output


def truncate_messages_safe(messages: list[dict], max_tokens: int) -> list[dict]:
    """Truncate message list without splitting tool-chain groups."""

    safe = validate_tool_chain(messages)
    limit = max(0, int(max_tokens))
    if limit <= 0:
        return safe

    def token_cost(msg: dict[str, Any]) -> int:
        content = msg.get("content", "")
        if isinstance(content, str):
            safe = sanitize_text(content)
            return max(1, len(safe.split())) if isinstance(safe, str) and safe.strip() else 1
        if isinstance(content, list):
            total = 0
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", block.get("content", ""))
                    safe = sanitize_text(text)
                    if isinstance(safe, str) and safe.strip():
                        total += max(1, len(safe.split()))
            return max(1, total) if total else 1
        return 1

    total = sum(token_cost(msg) for msg in safe)
    if total <= limit:
        return safe

    groups = find_tool_chain_groups(safe)
    group_by_assistant = {int(g["assistant_idx"]): g for g in groups}
    member_to_assistant: dict[int, int] = {}
    for group in groups:
        aidx = int(group["assistant_idx"])
        member_to_assistant[aidx] = aidx
        for tidx in group["tool_result_idxs"]:
            member_to_assistant[int(tidx)] = aidx
    latest_assistant = max(group_by_assistant.keys()) if group_by_assistant else -1

    # Build units (atomic deletable chunks).
    units: list[dict[str, Any]] = []
    consumed: set[int] = set()
    for idx, msg in enumerate(safe):
        if idx in consumed:
            continue
        if idx in group_by_assistant:
            g = group_by_assistant[idx]
            indexes = [idx] + [int(i) for i in g["tool_result_idxs"]]
            indexes = [i for i in indexes if 0 <= i < len(safe)]
            for i in indexes:
                consumed.add(i)
            units.append({"indexes": indexes, "assistant_idx": idx})
            continue
        consumed.add(idx)
        units.append({"indexes": [idx], "assistant_idx": member_to_assistant.get(idx, -1)})

    removable_units: list[int] = []
    for uidx, unit in enumerate(units):
        idxs = unit["indexes"]
        contains_system = any(str(safe[i].get("role", "")).strip().lower() == "system" for i in idxs)
        is_latest_group = unit.get("assistant_idx", -1) == latest_assistant and latest_assistant >= 0
        if not contains_system and not is_latest_group:
            removable_units.append(uidx)

    to_drop: set[int] = set()
    for uidx in removable_units:
        if total <= limit:
            break
        for i in units[uidx]["indexes"]:
            to_drop.add(i)
            total -= token_cost(safe[i])

    if total > limit:
        # Could not satisfy limit without violating safety invariants.
        return safe
    return [msg for i, msg in enumerate(safe) if i not in to_drop]
