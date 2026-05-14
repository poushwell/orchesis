"""Plugin: Allow/deny requests based on source IP."""

from __future__ import annotations

import ipaddress

from orchesis.plugins import PluginInfo


class IPAllowlistHandler:
    def _ip_in_networks(self, source_ip: str, cidrs: list[str]) -> bool:
        ip_obj = ipaddress.ip_address(source_ip)
        for item in cidrs:
            if ip_obj in ipaddress.ip_network(item, strict=False):
                return True
        return False

    def evaluate(self, rule, request, **kwargs):  # noqa: ANN001, ANN003
        _ = kwargs
        checked = ["ip_allowlist"]
        context = request.get("context")
        source_ip = context.get("source_ip") if isinstance(context, dict) else None
        if not isinstance(source_ip, str) or not source_ip.strip():
            return ["ip_allowlist: missing context.source_ip"], checked
        source_ip = source_ip.strip()
        denied = rule.get("denied_ips")
        if isinstance(denied, list):
            try:
                if self._ip_in_networks(
                    source_ip, [item for item in denied if isinstance(item, str)]
                ):
                    return [f"ip_allowlist: source_ip {source_ip} is denied"], checked
            except ValueError:
                return ["ip_allowlist: invalid denied_ips configuration"], checked
        allowed = rule.get("allowed_ips")
        if isinstance(allowed, list) and allowed:
            try:
                if not self._ip_in_networks(
                    source_ip, [item for item in allowed if isinstance(item, str)]
                ):
                    return [f"ip_allowlist: source_ip {source_ip} is not in allowlist"], checked
            except ValueError:
                return ["ip_allowlist: invalid allowed_ips configuration"], checked
        return [], checked


PLUGIN_INFO = PluginInfo(
    name="ip_allowlist",
    rule_type="ip_allowlist",
    version="1.0",
    description="Allow/deny based on source IP",
    handler=IPAllowlistHandler(),
)
