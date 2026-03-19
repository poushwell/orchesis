"""Discourse coherence metrics for NLCE Phase 9 (IACS)."""

from __future__ import annotations

import re


def compute_flow_coherence(messages: list[dict]) -> float:
    """FC = topic flow coherence. Bigram overlap between consecutive messages."""
    if len(messages) < 2:
        return 1.0
    scores: list[float] = []
    for i in range(1, len(messages)):
        prev = _get_text(messages[i - 1])
        curr = _get_text(messages[i])
        prev_bigrams = set(_bigrams(prev))
        curr_bigrams = set(_bigrams(curr))
        if not prev_bigrams and not curr_bigrams:
            scores.append(1.0)
        elif not prev_bigrams or not curr_bigrams:
            scores.append(0.0)
        else:
            overlap = len(prev_bigrams & curr_bigrams)
            scores.append(overlap / max(len(prev_bigrams), len(curr_bigrams)))
    return sum(scores) / len(scores) if scores else 1.0


def compute_entity_continuity(messages: list[dict]) -> float:
    """EC = entity continuity. filename_overlap + regex entities + trigrams."""
    if len(messages) < 2:
        return 1.0
    all_entities = [_extract_entities(m) for m in messages]
    scores: list[float] = []
    for i in range(1, len(all_entities)):
        prev = all_entities[i - 1]
        curr = all_entities[i]
        if not prev and not curr:
            scores.append(1.0)
        elif not prev or not curr:
            scores.append(0.0)
        else:
            overlap = len(prev & curr)
            scores.append(overlap / max(len(prev), len(curr)))
    return sum(scores) / len(scores) if scores else 1.0


def compute_headedness(messages: list[dict]) -> float:
    """HC = headedness coefficient. Ratio of on-topic vs off-topic turns."""
    if not messages:
        return 1.0
    on_topic = sum(1 for m in messages if _is_on_topic(m))
    return on_topic / len(messages)


def compute_iacs_full(messages: list[dict]) -> dict:
    """Full IACS: 0.40xFC + 0.35xEC + 0.25xHC."""
    fc = compute_flow_coherence(messages)
    ec = compute_entity_continuity(messages)
    hc = compute_headedness(messages)
    iacs = 0.40 * fc + 0.35 * ec + 0.25 * hc
    return {
        "iacs": round(iacs, 4),
        "fc": round(fc, 4),
        "ec": round(ec, 4),
        "hc": round(hc, 4),
    }


def _get_text(message: dict) -> str:
    content = message.get("content", "")
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


def _bigrams(text: str) -> list[tuple]:
    words = text.lower().split()
    return list(zip(words, words[1:]))


def _extract_entities(message: dict) -> set:
    text = _get_text(message)
    files = set(re.findall(r"\b[\w\-]+\.\w{2,4}\b", text))
    caps = set(re.findall(r"\b[A-Z][a-z]+\b", text))
    nums = set(re.findall(r"\b\d+\b", text))
    return files | caps | nums


def _is_on_topic(message: dict) -> bool:
    text = _get_text(message)
    return len(text.strip()) > 10
