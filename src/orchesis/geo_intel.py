"""Geo/IP threat context enrichment (stdlib only)."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any


class GeoIntel:
    """Enriches threats with geographic context (stdlib only, no external APIs)."""

    # Private IP ranges (RFC 1918, loopback, link-local)
    PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    ]

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self) -> None:
        self._networks = [ipaddress.ip_network(item) for item in self.PRIVATE_RANGES]

    def classify_ip(self, ip: str) -> dict:
        value = str(ip or "").strip()
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return {
                "ip": value,
                "type": "invalid",
                "is_private": False,
                "risk_hint": "unknown",
            }
        if addr.is_loopback:
            ip_type = "loopback"
            risk = "internal"
            private = True
        elif addr.is_link_local:
            ip_type = "link_local"
            risk = "internal"
            private = True
        elif any(addr in net for net in self._networks):
            ip_type = "private"
            risk = "internal"
            private = True
        else:
            ip_type = "public"
            risk = "external"
            private = False
        return {
            "ip": value,
            "type": ip_type,
            "is_private": private,
            "risk_hint": risk,
        }

    def enrich_threat(self, threat: dict) -> dict:
        """Add geo context to threat dict."""
        payload = dict(threat or {})
        text = json.dumps(payload, ensure_ascii=False)
        ips = self.extract_ips(text)
        payload["geo_context"] = {
            "ips": [self.classify_ip(ip) for ip in ips],
            "ssrf": self.scan_for_ssrf(text),
        }
        return payload

    def extract_ips(self, text: str) -> list[str]:
        """Extract all IP addresses from text."""
        source = str(text or "")
        out: list[str] = []
        seen: set[str] = set()
        for candidate in self._IP_RE.findall(source):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            out.append(candidate)
        return out

    def scan_for_ssrf(self, text: str) -> dict:
        """Detect SSRF attempts targeting private ranges."""
        targets: list[str] = []
        ranges: list[str] = []
        for ip in self.extract_ips(text):
            cls = self.classify_ip(ip)
            t = str(cls.get("type", "invalid"))
            if t in {"private", "loopback", "link_local"}:
                targets.append(ip)
                if t == "private":
                    try:
                        addr = ipaddress.ip_address(ip)
                        for net in self._networks:
                            if addr in net:
                                ranges.append(str(net))
                                break
                    except ValueError:
                        continue
                elif t == "loopback":
                    ranges.append("127.0.0.0/8")
                elif t == "link_local":
                    ranges.append("169.254.0.0/16")
        uniq_ranges = list(dict.fromkeys(ranges))
        detected = len(targets) > 0
        severity = "low"
        if detected:
            if any(ip.startswith("127.") or ip.startswith("169.254.") for ip in targets):
                severity = "critical"
            elif len(targets) >= 3:
                severity = "critical"
            elif len(targets) >= 2:
                severity = "high"
            else:
                severity = "medium"
        return {
            "ssrf_detected": detected,
            "target_ips": targets,
            "target_ranges": uniq_ranges,
            "severity": severity,
        }
