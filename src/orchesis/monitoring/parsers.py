"""Parsers and relevance scoring for social monitoring feeds."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class SocialMonitoringParsers:
    """Parse monitoring feeds for AI agent topics."""

    AI_AGENT_KEYWORDS = [
        "AI agent",
        "LLM proxy",
        "agent security",
        "prompt injection",
        "context window",
        "token cost",
        "OpenClaw",
        "LangChain agents",
        "AI governance",
        "EU AI Act",
        "MCP server",
    ]

    def parse_hn_item(self, item: dict) -> dict:
        """Parse HN API item into normalized format."""
        title = str(item.get("title", "") or "")
        text = str(item.get("text", "") or "")
        combined = f"{title} {text}".strip()
        matched = self._matched_keywords(combined)
        return {
            "id": str(item.get("id", "")),
            "title": title,
            "url": str(item.get("url", "") or ""),
            "points": int(item.get("score", 0) or 0),
            "comments": int(item.get("descendants", 0) or 0),
            "timestamp": self._ts(item.get("time")),
            "relevance_score": self.score_relevance(combined),
            "keywords_matched": matched,
        }

    def parse_reddit_post(self, post: dict) -> dict:
        """Parse Reddit post into normalized format."""
        title = str(post.get("title", "") or "")
        body = str(post.get("selftext", post.get("body", "")) or "")
        combined = f"{title} {body}".strip()
        matched = self._matched_keywords(combined)
        return {
            "id": str(post.get("id", "")),
            "title": title,
            "url": str(post.get("url", "") or ""),
            "points": int(post.get("score", 0) or 0),
            "comments": int(post.get("num_comments", 0) or 0),
            "timestamp": self._ts(post.get("created_utc", post.get("created_at"))),
            "relevance_score": self.score_relevance(combined),
            "keywords_matched": matched,
        }

    def parse_twitter_item(self, item: dict) -> dict:
        """Parse Twitter/X item."""
        text = str(item.get("text", "") or "")
        matched = self._matched_keywords(text)
        return {
            "id": str(item.get("id", "")),
            "title": text[:120],
            "url": str(item.get("url", "") or ""),
            "points": int(item.get("likes", item.get("favorite_count", 0)) or 0),
            "comments": int(item.get("replies", item.get("reply_count", 0)) or 0),
            "timestamp": self._ts(item.get("created_at")),
            "relevance_score": self.score_relevance(text),
            "keywords_matched": matched,
        }

    def score_relevance(self, text: str) -> float:
        """Score content relevance to AI agent topics. 0-1."""
        if not isinstance(text, str) or not text.strip():
            return 0.0
        text_l = text.lower()
        matched = self._matched_keywords(text)
        keyword_ratio = len(matched) / float(max(1, len(self.AI_AGENT_KEYWORDS)))
        ai_density = 0.0
        ai_tokens = ["agent", "llm", "prompt", "context", "token", "governance", "mcp"]
        words = [w for w in text_l.replace("\n", " ").split(" ") if w]
        if words:
            ai_hits = sum(1 for w in words if any(tok in w for tok in ai_tokens))
            ai_density = ai_hits / float(len(words))
        phrase_bonus = 0.0
        if len(matched) >= 2:
            phrase_bonus = 0.1
        score = min(1.0, (1.0 * keyword_ratio) + (0.6 * ai_density) + phrase_bonus)
        return round(score, 3)

    def extract_opportunities(self, items: list[dict]) -> list[dict]:
        """Find comment/engagement opportunities."""
        opportunities: list[dict] = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            relevance = float(item.get("relevance_score", 0.0) or 0.0)
            if relevance < 0.5:
                continue
            title = str(item.get("title", "") or "")
            title_l = title.lower()
            if "?" in title or "help" in title_l or "how" in title_l:
                opp_type = "answer"
                angle = "Provide practical implementation guidance and concrete examples."
            elif "launch" in title_l or "released" in title_l or "new" in title_l:
                opp_type = "share"
                angle = "Share Orchesis positioning with a concise feature comparison."
            else:
                opp_type = "engage"
                angle = "Engage with insights on AI agent security and governance."
            opportunities.append(
                {
                    "item": item,
                    "opportunity_type": opp_type,
                    "relevance": round(relevance, 3),
                    "suggested_angle": angle,
                }
            )
        opportunities.sort(key=lambda row: float(row.get("relevance", 0.0)), reverse=True)
        return opportunities

    def filter_by_relevance(self, items: list[dict], threshold: float = 0.5) -> list[dict]:
        """Filter to relevant items only."""
        out: list[dict] = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            relevance = item.get("relevance_score")
            if not isinstance(relevance, int | float):
                title = str(item.get("title", "") or "")
                relevance = self.score_relevance(title)
            if float(relevance) >= float(threshold):
                out.append(item)
        return out

    def _matched_keywords(self, text: str) -> list[str]:
        text_l = str(text or "").lower()
        return [kw for kw in self.AI_AGENT_KEYWORDS if kw.lower() in text_l]

    @staticmethod
    def _ts(raw: Any) -> str:
        if isinstance(raw, int | float):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
        if isinstance(raw, str) and raw.strip():
            return raw
        return datetime.now(timezone.utc).isoformat()
