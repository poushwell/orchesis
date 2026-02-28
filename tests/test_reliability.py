from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.reliability import ReliabilityReportGenerator


def test_reliability_report_generates(tmp_path: Path) -> None:
    generator = ReliabilityReportGenerator(
        corpus_path=str(Path(__file__).parent / "corpus"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        fuzz_log=str(tmp_path / "fuzz_runs.jsonl"),
        mutation_log=str(tmp_path / "mutation_runs.jsonl"),
        replay_log=str(tmp_path / "replay_runs.jsonl"),
    )
    report = generator.generate()
    assert report.generated_at
    assert report.orchesis_version
    assert report.total_tests >= 1
    assert report.corpus_entries >= 14


def test_reliability_markdown_format(tmp_path: Path) -> None:
    generator = ReliabilityReportGenerator(
        corpus_path=str(Path(__file__).parent / "corpus"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
    )
    markdown = generator.to_markdown(generator.generate())
    assert "# Orchesis Reliability Report" in markdown
    assert "## Testing" in markdown
    assert "## Fuzzing" in markdown
    assert "## Runtime Guarantees" in markdown


def test_reliability_json_format(tmp_path: Path) -> None:
    generator = ReliabilityReportGenerator(
        corpus_path=str(Path(__file__).parent / "corpus"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
    )
    payload = generator.to_json(generator.generate())
    parsed = json.loads(payload)
    assert "generated_at" in parsed
    assert "orchesis_version" in parsed
    assert "total_tests" in parsed


@pytest.mark.asyncio
async def test_reliability_api_endpoint(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
api:
  token: "orch_sk_test"
rules:
  - name: budget_limit
    max_cost_per_call: 1.0
""".strip(),
        encoding="utf-8",
    )
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/reliability",
            headers={"Authorization": "Bearer orch_sk_test"},
        )
    assert response.status_code == 200
    payload = response.json()
    assert "generated_at" in payload
    assert "orchesis_version" in payload
