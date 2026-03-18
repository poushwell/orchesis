"""Built-in searchable knowledge base."""

from __future__ import annotations

from typing import Any


class OrchesisKnowledgeBase:
    """Searchable knowledge base for Orchesis documentation and FAQs."""

    BUILT_IN_ARTICLES = {
        "what_is_orchesis": {
            "title": "What is Orchesis?",
            "content": "Orchesis is a transparent HTTP proxy and control-plane for AI agent governance.",
            "tags": ["intro", "overview"],
        },
        "quick_start": {
            "title": "Quick Start Guide",
            "content": "pip install orchesis && orchesis quickstart to bootstrap policies and API services.",
            "tags": ["setup", "getting-started"],
        },
        "eu_ai_act": {
            "title": "EU AI Act Compliance",
            "content": "Orchesis implements Articles 9, 12, and 72 controls through monitoring and decision logging.",
            "tags": ["compliance", "eu-ai-act"],
        },
        "token_yield": {
            "title": "Token Yield Explained",
            "content": "Token Yield equals semantic_tokens divided by total_tokens and helps optimize cost.",
            "tags": ["cost", "optimization"],
        },
    }

    def __init__(self) -> None:
        self._articles: dict[str, dict[str, Any]] = {
            key: dict(value) for key, value in self.BUILT_IN_ARTICLES.items()
        }

    @staticmethod
    def _normalize_article(article_id: str, article: dict[str, Any]) -> dict[str, Any]:
        tags = article.get("tags", [])
        safe_tags = [str(tag).strip().lower() for tag in tags if isinstance(tag, str) and tag.strip()]
        return {
            "article_id": str(article_id),
            "title": str(article.get("title", "") or ""),
            "content": str(article.get("content", "") or ""),
            "tags": safe_tags,
        }

    def search(self, query: str) -> list[dict]:
        """Search articles by keyword."""
        needle = str(query or "").strip().lower()
        if not needle:
            return []
        rows: list[tuple[int, dict[str, Any]]] = []
        for article_id, article in self._articles.items():
            normalized = self._normalize_article(article_id, article)
            title = normalized["title"].lower()
            content = normalized["content"].lower()
            tags = [str(tag).lower() for tag in normalized["tags"]]
            score = 0
            if needle in title:
                score += 5
            if needle in content:
                score += 3
            if any(needle in tag for tag in tags):
                score += 4
            if score > 0:
                rows.append((score, normalized))
        rows.sort(key=lambda item: item[0], reverse=True)
        return [row for _, row in rows]

    def get_article(self, article_id: str) -> dict | None:
        row = self._articles.get(str(article_id))
        if not isinstance(row, dict):
            return None
        return self._normalize_article(str(article_id), row)

    def add_article(self, article_id: str, article: dict) -> bool:
        if not isinstance(article_id, str) or not article_id.strip():
            return False
        if not isinstance(article, dict):
            return False
        self._articles[article_id.strip()] = dict(article)
        return True

    def list_by_tag(self, tag: str) -> list[dict]:
        needle = str(tag or "").strip().lower()
        if not needle:
            return []
        rows: list[dict[str, Any]] = []
        for article_id, article in self._articles.items():
            normalized = self._normalize_article(article_id, article)
            if needle in normalized["tags"]:
                rows.append(normalized)
        rows.sort(key=lambda item: str(item.get("article_id", "")))
        return rows

    def suggest_for_error(self, error_message: str) -> list[dict]:
        """Suggest relevant articles based on error."""
        text = str(error_message or "").lower()
        if not text:
            return []
        suggestions: list[dict[str, Any]] = []
        if any(token in text for token in ["401", "403", "auth", "token", "unauthorized"]):
            item = self.get_article("quick_start")
            if item:
                suggestions.append(item)
        if any(token in text for token in ["eu ai", "compliance", "article 12", "article 9"]):
            item = self.get_article("eu_ai_act")
            if item:
                suggestions.append(item)
        if any(token in text for token in ["cost", "budget", "token", "yield"]):
            item = self.get_article("token_yield")
            if item:
                suggestions.append(item)
        if not suggestions:
            fallback = self.get_article("what_is_orchesis")
            if fallback:
                suggestions.append(fallback)
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for item in suggestions:
            article_id = str(item.get("article_id", ""))
            if article_id and article_id not in seen:
                seen.add(article_id)
                deduped.append(item)
        return deduped

