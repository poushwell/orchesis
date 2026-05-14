"""Basic Orchesis SDK usage example."""

from __future__ import annotations

from orchesis.client import OrchesisClient


def main() -> None:
    client = OrchesisClient("http://localhost:8080", api_token="orch_sk_example")

    allowed = client.is_allowed(
        "read_file", params={"path": "/data/report.csv"}, agent_id="demo_agent"
    )
    print(f"read_file /data/report.csv allowed: {allowed}")

    denied = client.evaluate(
        tool="run_sql",
        params={"query": "DROP TABLE users"},
        cost=0.1,
        agent_id="demo_agent",
    )
    print(f"run_sql DROP allowed: {denied.allowed}")
    if not denied:
        print("deny reasons:", denied.reasons)


if __name__ == "__main__":
    main()
