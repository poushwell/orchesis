"""Policy Library - curated production-ready policy templates."""

from __future__ import annotations

LIBRARY = {
    "openclaw_secure": {
        "name": "OpenClaw Secure",
        "description": "Hardened policy for OpenClaw agents",
        "use_case": "Production OpenClaw fleet with full security",
        "policy": {
            "proxy": {"host": "0.0.0.0", "port": 8080},
            "security": {"enabled": True, "block_on_match": True},
            "semantic_cache": {"enabled": True, "similarity_threshold": 0.92},
            "recording": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 3},
            "budgets": {"daily": 50.0, "per_request": 0.50},
            "threat_intel": {"enabled": True},
        },
    },
    "research_permissive": {
        "name": "Research Permissive",
        "description": "Low-restriction policy for research agents",
        "use_case": "Internal research, no budget constraints",
        "policy": {
            "proxy": {"host": "0.0.0.0", "port": 8080},
            "security": {"enabled": True, "block_on_match": False},
            "semantic_cache": {"enabled": False},
            "recording": {"enabled": True},
            "loop_detection": {"enabled": True, "block_threshold": 10},
        },
    },
    "eu_ai_act_compliant": {
        "name": "EU AI Act Compliant",
        "description": "Full compliance with EU AI Act Articles 9, 12, 72",
        "use_case": "Enterprise deployment in EU",
        "policy": {
            "proxy": {"host": "0.0.0.0", "port": 8080},
            "security": {"enabled": True},
            "recording": {"enabled": True, "retention_days": 90},
            "evidence_record": {"enabled": True},
            "budgets": {"daily": 100.0},
            "threat_intel": {"enabled": True},
            "compliance": {"eu_ai_act": True, "articles": [9, 12, 72]},
        },
    },
    "cost_optimized": {
        "name": "Cost Optimized",
        "description": "Maximum cost reduction",
        "use_case": "High-volume, cost-sensitive deployments",
        "policy": {
            "proxy": {"host": "0.0.0.0", "port": 8080},
            "semantic_cache": {"enabled": True, "similarity_threshold": 0.88},
            "uci_compression": {"enabled": True},
            "context_budget": {"enabled": True},
            "budgets": {"daily": 20.0},
            "loop_detection": {"enabled": True},
        },
    },
    "minimal_dev": {
        "name": "Minimal Dev",
        "description": "Lightweight policy for local development",
        "use_case": "Development and testing",
        "policy": {
            "proxy": {"host": "127.0.0.1", "port": 8080},
            "security": {"enabled": False},
            "recording": {"enabled": False},
        },
    },
}


class PolicyLibrary:
    def list_templates(self) -> list[dict]:
        return [{"id": k, "name": v["name"], "use_case": v["use_case"]} for k, v in LIBRARY.items()]

    def get_template(self, template_id: str) -> dict | None:
        return LIBRARY.get(template_id)

    def get_policy(self, template_id: str) -> dict | None:
        template = LIBRARY.get(template_id)
        return template["policy"] if template else None

    def search(self, use_case_keyword: str) -> list[dict]:
        kw = str(use_case_keyword).lower()
        return [
            {"id": k, **v}
            for k, v in LIBRARY.items()
            if kw in v["use_case"].lower() or kw in v["description"].lower()
        ]

    def count(self) -> int:
        return len(LIBRARY)

