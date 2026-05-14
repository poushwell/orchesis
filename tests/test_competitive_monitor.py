from __future__ import annotations

from orchesis.monitoring.competitive import CompetitiveMonitor


def test_competitor_checked() -> None:
    mon = CompetitiveMonitor()
    row = mon.check_competitor("openguard", {"stars": 10})
    assert row["name"] == "openguard"
    assert "triggered" in row


def test_trigger_fires_above_threshold() -> None:
    mon = CompetitiveMonitor()
    row = mon.check_competitor("openguard", {"stars": 150})
    assert row["triggered"] is True
    assert row["trigger_type"] == "competitor_stars_spike"


def test_no_trigger_below_threshold() -> None:
    mon = CompetitiveMonitor()
    row = mon.check_competitor("dashclaw", {"stars": 120})
    assert row["triggered"] is False


def test_ecosystem_changes_detected() -> None:
    mon = CompetitiveMonitor()
    changes = mon.detect_ecosystem_changes(
        [
            {"title": "OpenAI launches new agent gateway", "source": "blog"},
            {"title": "Local meetup notes", "source": "forum"},
        ]
    )
    assert len(changes) >= 1
    assert changes[0]["event"] in mon.TRIGGER_EVENTS


def test_weekly_report_generated() -> None:
    mon = CompetitiveMonitor()
    report = mon.generate_weekly_report(
        {
            "competitors": {"openguard": {"stars": 120}},
            "feed": [{"title": "Major AI incident in production", "source": "news"}],
        }
    )
    assert "week" in report
    assert isinstance(report["threats"], list)
    assert isinstance(report["actions"], list)


def test_threat_level_scored() -> None:
    mon = CompetitiveMonitor()
    score = mon.score_threat_level("helicone", {"stars": 3000, "weekly_growth": 12})
    assert 0.0 <= score <= 1.0


def test_opportunity_identified() -> None:
    mon = CompetitiveMonitor()
    report = mon.generate_weekly_report(
        {
            "competitors": {"dashclaw": {"stars": 10}},
            "feed": [{"title": "Major AI incident at large vendor", "source": "news"}],
        }
    )
    assert isinstance(report["opportunities"], list)
    assert len(report["opportunities"]) >= 1


def test_all_competitors_covered() -> None:
    mon = CompetitiveMonitor()
    assert set(mon.COMPETITORS.keys()) == {"openguard", "dashclaw", "toran_sh", "helicone"}
