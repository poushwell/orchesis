from __future__ import annotations

from orchesis.config_validator import ConfigValidator


def test_valid_minimal_policy() -> None:
    validator = ConfigValidator()
    result = validator.validate({"proxy": {"port": 8090}})
    assert result["valid"] is True


def test_missing_required_section_error() -> None:
    validator = ConfigValidator()
    result = validator.validate({})
    assert result["valid"] is False
    assert any("Missing required section: proxy" in err for err in result["errors"])


def test_missing_recommended_warning() -> None:
    validator = ConfigValidator()
    result = validator.validate({"proxy": {"port": 8090}})
    assert len(result["warnings"]) > 0
    assert any("Missing recommended section: security" in w for w in result["warnings"])


def test_wrong_type_error() -> None:
    validator = ConfigValidator()
    result = validator.validate({"proxy": {"port": "8090"}, "budgets": {"daily": "100"}})
    assert "proxy.port must be integer" in result["errors"]
    assert "budgets.daily must be numeric" in result["errors"]


def test_score_computed() -> None:
    validator = ConfigValidator()
    result = validator.validate({"proxy": {"port": 8090}})
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 1.0


def test_grade_assigned() -> None:
    validator = ConfigValidator()
    result = validator.validate({"proxy": {"port": 8090}})
    assert result["grade"] in {"A", "B", "C"}


def test_suggestions_generated() -> None:
    validator = ConfigValidator()
    suggestions = validator.suggest_additions({"proxy": {"port": 8090}})
    assert len(suggestions) >= 1
    assert any("semantic_cache" in item for item in suggestions)


def test_full_policy_high_score() -> None:
    validator = ConfigValidator()
    policy = {
        "proxy": {"port": 8090},
        "security": {},
        "semantic_cache": {},
        "recording": {},
        "loop_detection": {},
        "budgets": {"daily": 100.0},
        "threat_intel": {},
        "uci_compression": {},
        "context_budget": {},
        "apoptosis": {},
        "injection_protocol": {},
        "thompson_sampling": {},
        "hgt_protocol": {},
        "quorum_sensing": {},
    }
    result = validator.validate(policy)
    assert result["valid"] is True
    assert result["score"] >= 0.95
    assert result["grade"] == "A"
