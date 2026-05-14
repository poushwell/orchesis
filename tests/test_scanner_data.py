from __future__ import annotations

import json
from pathlib import Path


DATA_DIR = Path("src/orchesis/scanner_data")
CVE_DB_PATH = DATA_DIR / "scanner_cve_database.json"
OWASP_PATH = DATA_DIR / "owasp_mcp_mapping.json"
SELF_AUDIT_PATH = DATA_DIR / "orchesis_self_audit_rules.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_cve_database_valid_json() -> None:
    data = _load(CVE_DB_PATH)
    assert isinstance(data, dict)


def test_cve_database_has_malicious() -> None:
    data = _load(CVE_DB_PATH)
    rows = data.get("malicious_packages")
    assert isinstance(rows, list)
    assert len(rows) > 0


def test_cve_database_has_vulnerable() -> None:
    data = _load(CVE_DB_PATH)
    rows = data.get("vulnerable_packages")
    assert isinstance(rows, list)
    assert len(rows) > 0


def test_cve_database_fields() -> None:
    data = _load(CVE_DB_PATH)
    rows = list(data.get("malicious_packages", [])) + list(data.get("vulnerable_packages", []))
    assert rows
    for item in rows:
        assert isinstance(item, dict)
        assert "name" in item and item["name"]
        assert "severity" in item and item["severity"]


def test_owasp_mapping_valid_json() -> None:
    data = _load(OWASP_PATH)
    assert isinstance(data, dict)


def test_owasp_mapping_has_10() -> None:
    data = _load(OWASP_PATH)
    rows = data.get("owasp_mcp")
    assert isinstance(rows, list)
    assert len(rows) == 10


def test_owasp_mapping_ids() -> None:
    data = _load(OWASP_PATH)
    rows = data.get("owasp_mcp", [])
    ids = [item.get("id") for item in rows if isinstance(item, dict)]
    assert ids == [f"MCP{i:02d}" for i in range(1, 11)]


def test_self_audit_valid_json() -> None:
    data = _load(SELF_AUDIT_PATH)
    assert isinstance(data, dict)


def test_self_audit_has_checks() -> None:
    data = _load(SELF_AUDIT_PATH)
    checks = data.get("checks")
    assert isinstance(checks, list)
    assert len(checks) >= 10


def test_self_audit_fields() -> None:
    data = _load(SELF_AUDIT_PATH)
    checks = data.get("checks", [])
    assert checks
    for check in checks:
        assert isinstance(check, dict)
        for key in ("id", "field", "severity", "message", "fix"):
            assert key in check
            assert check[key]
