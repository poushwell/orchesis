"""Standalone plugin module wrapper for PII detector."""

from __future__ import annotations

from orchesis.contrib.pii_detector import PIIDetectorHandler, PiiDetectorPlugin
from orchesis.plugins import PluginInfo

PLUGIN_INFO = PluginInfo(
    name="pii_detector",
    rule_type="pii_detector",
    version="2.0",
    description="Detect and block tool calls containing sensitive PII",
    handler=PIIDetectorHandler(),
)

__all__ = ["PiiDetectorPlugin", "PLUGIN_INFO"]
