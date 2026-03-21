"""CASURA STIX 2.1 export utilities."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from orchesis.casura.api_v2 import Incident

CASURA_KILL_CHAIN = {
    "prompt_injection": "initial-access",
    "data_exfiltration": "exfiltration",
    "model_poisoning": "resource-development",
    "denial_of_service": "impact",
    "privilege_escalation": "privilege-escalation",
    "supply_chain": "resource-development",
    "output_manipulation": "impact",
    "resource_abuse": "impact",
    "privacy_violation": "collection",
    "alignment_failure": "impact",
    "tool_misuse": "execution",
    "context_manipulation": "initial-access",
}


class StixExporter:
    """Generate STIX 2.1 bundles from CASURA incidents."""

    def _incident_to_attack_pattern(self, incident: Incident) -> dict:
        attack_pattern: dict = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{uuid4()}",
            "name": incident.title,
            "description": incident.description,
            "x_aiss_severity": float(incident.severity),
            "x_casura_category": incident.category,
            "x_casura_incident_id": incident.incident_id,
            "kill_chain_phases": [
                {
                    "kill_chain_name": "casura-ai-threat-taxonomy",
                    "phase_name": CASURA_KILL_CHAIN.get(incident.category, "impact"),
                }
            ],
        }

        if incident.tags:
            attack_pattern["labels"] = list(incident.tags)

        if incident.cve_ids:
            refs = []
            for cve in incident.cve_ids:
                refs.append(
                    {
                        "source_name": "cve",
                        "external_id": cve,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    }
                )
            attack_pattern["external_references"] = refs

        return attack_pattern

    def export_bundle(self, incidents: list[Incident]) -> dict:
        return {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": [self._incident_to_attack_pattern(incident) for incident in incidents],
        }

    def export_to_file(self, incidents: list[Incident], path: str) -> None:
        payload = self.export_bundle(incidents)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
