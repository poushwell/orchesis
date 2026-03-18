from __future__ import annotations

from orchesis.monitoring.parsers import SocialMonitoringParsers


def test_hn_item_parsed() -> None:
    p = SocialMonitoringParsers()
    row = p.parse_hn_item(
        {
            "id": 101,
            "title": "AI agent security for MCP server",
            "url": "https://news.ycombinator.com/item?id=101",
            "score": 42,
            "descendants": 12,
            "time": 1700000000,
        }
    )
    assert row["id"] == "101"
    assert row["points"] == 42
    assert isinstance(row["keywords_matched"], list)


def test_reddit_post_parsed() -> None:
    p = SocialMonitoringParsers()
    row = p.parse_reddit_post(
        {
            "id": "abc",
            "title": "Prompt injection in LangChain agents",
            "selftext": "Need mitigation strategies",
            "score": 30,
            "num_comments": 8,
            "created_utc": 1700000010,
        }
    )
    assert row["id"] == "abc"
    assert row["comments"] == 8
    assert row["relevance_score"] > 0


def test_relevance_scored() -> None:
    p = SocialMonitoringParsers()
    score = p.score_relevance("AI governance and token cost optimization")
    assert 0.0 <= score <= 1.0


def test_high_relevance_keyword_match() -> None:
    p = SocialMonitoringParsers()
    score = p.score_relevance("AI agent prompt injection defense for MCP server")
    assert score >= 0.5


def test_low_relevance_filtered() -> None:
    p = SocialMonitoringParsers()
    rows = [
        {"title": "Gardening tools and weather", "relevance_score": 0.1},
        {"title": "MCP server hardening guide", "relevance_score": 0.8},
    ]
    out = p.filter_by_relevance(rows, threshold=0.5)
    assert len(out) == 1
    assert out[0]["relevance_score"] == 0.8


def test_opportunities_extracted() -> None:
    p = SocialMonitoringParsers()
    rows = [
        {"title": "How to secure AI agent?", "relevance_score": 0.9},
        {"title": "Irrelevant sports post", "relevance_score": 0.1},
    ]
    out = p.extract_opportunities(rows)
    assert len(out) == 1
    assert out[0]["opportunity_type"] in {"answer", "share", "engage"}


def test_answer_opportunity_identified() -> None:
    p = SocialMonitoringParsers()
    rows = [{"title": "How to prevent prompt injection?", "relevance_score": 0.92}]
    out = p.extract_opportunities(rows)
    assert out[0]["opportunity_type"] == "answer"


def test_filter_by_threshold() -> None:
    p = SocialMonitoringParsers()
    rows = [{"title": "AI governance update", "relevance_score": 0.6}, {"title": "foo", "relevance_score": 0.4}]
    out = p.filter_by_relevance(rows, threshold=0.6)
    assert len(out) == 1
