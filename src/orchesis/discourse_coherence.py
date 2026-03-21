"""Discourse coherence metrics for NLCE Phase 9 (IACS)."""

from __future__ import annotations

import re


def _preprocess_messages(messages: list[dict]) -> list[dict]:
    """Single-pass preprocessing for discourse coherence metrics."""
    preprocessed: list[dict] = []
    for msg in messages:
        text = _get_text(msg)
        tokens = re.findall(r"\b\w+\b", text.lower())
        bigrams = {(tokens[i], tokens[i + 1]) for i in range(len(tokens) - 1)}
        files = set(re.findall(r"\b[\w\-]+\.\w{2,4}\b", text))
        caps = set(re.findall(r"\b[A-Z][a-z]+\b", text))
        nums = set(re.findall(r"\b\d+\b", text))
        has_header = bool(re.search(r"^#{1,6}\s|^\*\*[^*]+\*\*$", text, re.MULTILINE))
        has_list = bool(re.search(r"^\s*[-*•]\s|^\s*\d+\.\s", text, re.MULTILINE))
        preprocessed.append(
            {
                "text": text,
                "tokens": tokens,
                "bigrams": bigrams,
                "entities": files | caps | nums,
                "has_header": has_header,
                "has_list": has_list,
                "word_count": len(tokens),
            }
        )
    return preprocessed


def compute_flow_coherence(messages: list[dict], _preprocessed: list[dict] | None = None) -> float:
    """FC = topic flow coherence. Bigram overlap between consecutive messages."""
    prep = _preprocessed or _preprocess_messages(messages)
    if len(prep) < 2:
        return 1.0
    scores: list[float] = []
    for i in range(1, len(prep)):
        prev_bigrams = prep[i - 1]["bigrams"]
        curr_bigrams = prep[i]["bigrams"]
        if not prev_bigrams and not curr_bigrams:
            scores.append(1.0)
        elif not prev_bigrams or not curr_bigrams:
            scores.append(0.0)
        else:
            overlap = len(prev_bigrams & curr_bigrams) / max(len(prev_bigrams | curr_bigrams), 1)
            scores.append(overlap)
    return sum(scores) / len(scores) if scores else 1.0


def compute_entity_continuity(messages: list[dict], _preprocessed: list[dict] | None = None) -> float:
    """EC = entity continuity. filename_overlap + regex entities + trigrams."""
    prep = _preprocessed or _preprocess_messages(messages)
    if len(prep) < 2:
        return 1.0
    scores: list[float] = []
    for i in range(1, len(prep)):
        prev = prep[i - 1]["entities"]
        curr = prep[i]["entities"]
        if not prev and not curr:
            scores.append(1.0)
        elif not prev or not curr:
            scores.append(0.0)
        else:
            overlap = len(prev & curr)
            scores.append(overlap / max(len(prev | curr), 1))
    return sum(scores) / len(scores) if scores else 1.0


def compute_headedness(messages: list[dict], _preprocessed: list[dict] | None = None) -> float:
    """HC = headedness coefficient. Ratio of on-topic vs off-topic turns."""
    prep = _preprocessed or _preprocess_messages(messages)
    if not prep:
        return 1.0
    structured = sum(
        1
        for item in prep
        if item["has_header"] or item["has_list"] or item["word_count"] > 10
    )
    return structured / len(prep)


def compute_iacs_full(messages: list[dict]) -> dict:
    """Full IACS: 0.40xFC + 0.35xEC + 0.25xHC."""
    prep = _preprocess_messages(messages)
    fc = compute_flow_coherence(messages, _preprocessed=prep)
    ec = compute_entity_continuity(messages, _preprocessed=prep)
    hc = compute_headedness(messages, _preprocessed=prep)
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
        return " ".join(
            p.get("text", "")
            for p in content
            if isinstance(p, dict) and (p.get("type") in {None, "text"})
        )
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
