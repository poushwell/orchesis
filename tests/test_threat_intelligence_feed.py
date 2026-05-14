from __future__ import annotations

from orchesis.threat_feed import ThreatFeed


def test_community_feed_returned() -> None:
    feed = ThreatFeed({})
    feed.submit_threat("prompt-injection", "high", {})
    rows = feed.get_community_feed()
    assert isinstance(rows, list)
    assert rows


def test_threat_submitted() -> None:
    feed = ThreatFeed({})
    row = feed.submit_threat("jailbreak-pattern", "critical", {"source": "user"})
    assert row["signature"] == "jailbreak-pattern"
    assert row["severity"] == "critical"
    assert row["source"] == "community"


def test_trending_threats_ranked() -> None:
    feed = ThreatFeed({})
    for _ in range(3):
        feed.submit_threat("sig-a", "high", {})
    for _ in range(2):
        feed.submit_threat("sig-b", "medium", {})
    top = feed.get_trending_threats(limit=2)
    assert len(top) == 2
    assert top[0]["reports"] >= top[1]["reports"]
    assert top[0]["signature"] == "sig-a"


def test_feed_exported_json() -> None:
    feed = ThreatFeed({})
    feed.submit_threat("sig-json", "low", {})
    text = feed.export_feed("json")
    assert '"feed"' in text
    assert "sig-json" in text


def test_feed_exported_yaml() -> None:
    feed = ThreatFeed({})
    feed.submit_threat("sig-yaml", "medium", {})
    text = feed.export_feed("yaml")
    assert "feed:" in text
    assert "sig-yaml" in text


def test_verified_threats_flagged() -> None:
    feed = ThreatFeed({})
    row = feed.submit_threat("sig-verified", "high", {"verified": True})
    assert row["verified"] is True


def test_severity_levels_present() -> None:
    feed = ThreatFeed({})
    feed.submit_threat("sig-critical", "critical", {})
    feed.submit_threat("sig-low", "low", {})
    severities = {item["severity"] for item in feed.get_community_feed()}
    assert "critical" in severities
    assert "low" in severities


def test_feed_bounded() -> None:
    feed = ThreatFeed({"feed_limit": 50})
    for i in range(120):
        feed.submit_threat(f"sig-{i}", "medium", {})
    rows = feed.get_community_feed()
    assert len(rows) <= 50
