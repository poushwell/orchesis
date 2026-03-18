from __future__ import annotations

from orchesis.are.framework import AREFramework


def test_slo_defined() -> None:
    fw = AREFramework()
    row = fw.define_slo("api-availability", "availability", 0.99, window_days=30)
    assert row["name"] == "api-availability"
    assert row["sli"] == "availability"
    assert row["target"] == 0.99


def test_sli_recorded() -> None:
    fw = AREFramework()
    fw.define_slo("latency", "latency_p99", 400.0)
    fw.record_sli("latency", 350.0)
    budget = fw.get_error_budget("latency")
    assert budget["current"] == 350.0


def test_error_budget_computed() -> None:
    fw = AREFramework()
    fw.define_slo("availability", "availability", 0.99)
    fw.record_sli("availability", 0.995)
    payload = fw.get_error_budget("availability")
    assert payload["budget_remaining"] >= 0.0
    assert payload["exhausted"] is False


def test_burn_rate_calculated() -> None:
    fw = AREFramework()
    fw.define_slo("error-rate", "error_rate", 0.02)
    fw.record_sli("error-rate", 0.03)
    payload = fw.get_error_budget("error-rate")
    assert payload["burn_rate"] > 0.0


def test_budget_exhausted_flag() -> None:
    fw = AREFramework()
    fw.define_slo("error-rate", "error_rate", 0.02)
    fw.record_sli("error-rate", 0.08)
    payload = fw.get_error_budget("error-rate")
    assert payload["exhausted"] is True


def test_reliability_report_generated() -> None:
    fw = AREFramework()
    fw.define_slo("availability", "availability", 0.99)
    fw.define_slo("latency", "latency_p99", 400.0)
    fw.record_sli("availability", 0.995)
    fw.record_sli("latency", 350.0)
    report = fw.get_reliability_report()
    assert report["total_slos"] == 2
    assert isinstance(report["slos"], list)


def test_burn_rate_alert_triggered() -> None:
    fw = AREFramework()
    fw.define_slo("error-rate", "error_rate", 0.01)
    fw.record_sli("error-rate", 0.05)
    alert = fw.get_burn_rate_alert("error-rate")
    assert alert is not None
    assert alert["severity"] in {"warning", "critical"}


def test_multiple_slos_independent() -> None:
    fw = AREFramework()
    fw.define_slo("availability", "availability", 0.99)
    fw.define_slo("security", "security_rate", 0.95)
    fw.record_sli("availability", 0.995)
    fw.record_sli("security", 0.90)
    a = fw.get_error_budget("availability")
    b = fw.get_error_budget("security")
    assert a["slo_name"] == "availability"
    assert b["slo_name"] == "security"
    assert a["current"] != b["current"]
