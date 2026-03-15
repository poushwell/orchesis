"""Telegram alert integration for Orchesis events."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from orchesis.integrations.base import AlertEvent, BaseIntegration
from orchesis.structured_log import StructuredLogger
from orchesis.telemetry import DecisionEvent

DEFAULT_NOTIFY_ON = ["DENY", "ANOMALY"]
COMMANDS = {
    "/status": "Текущий статус proxy (uptime, requests, threats)",
    "/budget": "Расход бюджета сегодня и прогноз",
    "/threats": "Последние 10 угроз",
    "/agents": "Активные агенты и их reliability score",
    "/block <pattern>": "Добавить паттерн в blocklist",
    "/pause": "Приостановить proxy (только мониторинг)",
    "/resume": "Возобновить proxy",
    "/help": "Список команд",
}


def _get_httpx():
    try:
        import httpx

        return httpx
    except ImportError:
        raise ImportError(
            "httpx is required for Telegram integration. "
            "Install with: pip install orchesis[integrations]"
        ) from None


def _escape_markdown_v2(value: str) -> str:
    """Escape Telegram MarkdownV2 special characters."""
    chars = r"_*[]()~`>#+-=|{}.!\\"
    escaped = value
    for char in chars:
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


def _format_uptime(seconds: int | float) -> str:
    total = max(0, int(seconds or 0))
    hours, rem = divmod(total, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{hours}h {minutes}m"


class TelegramBot:
    """Telegram bot with simple command handling."""

    def __init__(self, token: str, chat_id: str, proxy_instance: Any = None):
        self._token = token
        self._chat_id = chat_id
        self._proxy = proxy_instance
        self._offset = 0
        self._running = False
        self._logger = StructuredLogger("telegram_bot")

    async def _api_post(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        httpx = _get_httpx()
        url = f"https://api.telegram.org/bot{self._token}/{method}"
        response = await httpx.AsyncClient(timeout=10.0).post(url, json=payload)
        response.raise_for_status()
        body = response.json()
        return body if isinstance(body, dict) else {}

    async def _get_updates(self) -> list[dict[str, Any]]:
        payload = {"timeout": 20, "offset": self._offset + 1}
        try:
            data = await self._api_post("getUpdates", payload)
        except Exception as error:  # noqa: BLE001
            self._logger.warn("telegram getUpdates failed", error=str(error))
            return []
        result = data.get("result", [])
        if isinstance(result, list):
            return [item for item in result if isinstance(item, dict)]
        return []

    async def send(self, text: str) -> bool:
        payload = {"chat_id": self._chat_id, "text": str(text or "")}
        try:
            await self._api_post("sendMessage", payload)
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("telegram bot send failed", error=str(error))
            return False

    def _proxy_call(self, name: str, default: Any = None) -> Any:
        if self._proxy is None:
            return default
        target = getattr(self._proxy, name, None)
        if callable(target):
            try:
                return target()
            except Exception:
                return default
        return default

    def _format_status(self) -> str:
        stats = self._proxy_call("get_status_snapshot", {}) or {}
        uptime = _format_uptime(stats.get("uptime_seconds", 0))
        requests = int(stats.get("requests", 0) or 0)
        blocked = int(stats.get("blocked", 0) or 0)
        saved = float(stats.get("saved_usd", 0.0) or 0.0)
        return "\n".join(
            [
                "✅ ALL CLEAR",
                f"Uptime: {uptime}",
                f"Requests: {requests:,}",
                f"Blocked: {blocked:,}",
                f"Saved: ${saved:.2f}",
            ]
        )

    def _format_budget(self) -> str:
        budget = self._proxy_call("get_budget_snapshot", {}) or {}
        spent = float(budget.get("spent_usd", budget.get("spent", 0.0)) or 0.0)
        limit = float(budget.get("limit_usd", budget.get("limit", 0.0)) or 0.0)
        rate = float(budget.get("rate_per_hour", 0.0) or 0.0)
        projected = float(budget.get("projected_24h", 0.0) or 0.0)
        eta = str(budget.get("eta", "n/a"))
        return "\n".join(
            [
                "💸 BUDGET WARNING",
                f"Spent: ${spent:.2f} / ${limit:.2f}",
                f"Rate: ${rate:.2f}/hour",
                f"Projected: ${projected:.2f} in {eta}",
            ]
        )

    def _format_threats(self) -> str:
        rows = self._proxy_call("get_recent_threats", []) or []
        if not isinstance(rows, list) or not rows:
            return "No recent threats."
        lines = ["🚨 Last 10 threats:"]
        for item in rows[:10]:
            if isinstance(item, dict):
                rid = str(item.get("rule_id", "n/a"))
                ag = str(item.get("agent_id", "unknown"))
                sev = str(item.get("severity", "low")).upper()
                lines.append(f"- {sev} | {ag} | {rid}")
        return "\n".join(lines)

    def _format_agents(self) -> str:
        rows = self._proxy_call("get_agents_snapshot", []) or []
        if not isinstance(rows, list) or not rows:
            return "No active agents."
        lines = ["🤖 Active agents:"]
        for item in rows[:10]:
            if isinstance(item, dict):
                aid = str(item.get("agent_id", "unknown"))
                score = item.get("reliability_score", item.get("ars_score", "n/a"))
                lines.append(f"- {aid}: {score}")
        return "\n".join(lines)

    async def _handle_command(self, update: dict[str, Any]) -> None:
        if not isinstance(update, dict):
            return
        update_id = int(update.get("update_id", 0) or 0)
        if update_id > self._offset:
            self._offset = update_id
        msg = update.get("message", {})
        text = str(msg.get("text", "") or "").strip()
        if not text:
            return
        if text == "/status":
            await self.send(self._format_status())
        elif text == "/budget":
            await self.send(self._format_budget())
        elif text == "/threats":
            await self.send(self._format_threats())
        elif text == "/agents":
            await self.send(self._format_agents())
        elif text.startswith("/block "):
            pattern = text[7:].strip()
            fn = getattr(self._proxy, "add_block_pattern", None)
            if callable(fn) and pattern:
                fn(pattern)
                await self.send(f"✅ Blocked: {pattern}")
            else:
                await self.send("Unable to add block pattern.")
        elif text == "/pause":
            fn = getattr(self._proxy, "set_monitoring_only", None)
            if callable(fn):
                fn(True)
                await self.send("⏸ Proxy paused (monitoring only)")
            else:
                await self.send("Pause command unavailable.")
        elif text == "/resume":
            fn = getattr(self._proxy, "set_monitoring_only", None)
            if callable(fn):
                fn(False)
                await self.send("▶️ Proxy resumed")
            else:
                await self.send("Resume command unavailable.")
        elif text == "/help":
            help_lines = ["Available commands:"]
            for key, desc in COMMANDS.items():
                help_lines.append(f"{key} — {desc}")
            await self.send("\n".join(help_lines))

    async def poll_commands(self) -> None:
        """Long polling for commands from Telegram chat."""
        self._running = True
        while self._running:
            updates = await self._get_updates()
            for update in updates:
                await self._handle_command(update)
            await asyncio.sleep(1)

    def stop(self) -> None:
        self._running = False


class TelegramIntegration(BaseIntegration):
    """Telegram integration for AlertEvent notifications."""

    def __init__(self, config: dict[str, Any], proxy_instance: Any = None) -> None:
        super().__init__(config)
        self._token = str(self.config.get("token", "") or "")
        self._chat_id = str(self.config.get("chat_id", "") or "")
        self._logger = StructuredLogger("telegram_integration")
        self._bot = TelegramBot(self._token, self._chat_id, proxy_instance=proxy_instance)
        self._thread: threading.Thread | None = None

    def start_polling(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return

        def _runner() -> None:
            try:
                asyncio.run(self._bot.poll_commands())
            except Exception as error:  # noqa: BLE001
                self._logger.warn("telegram polling stopped", error=str(error))

        self._thread = threading.Thread(target=_runner, daemon=True, name="orchesis-telegram-bot")
        self._thread.start()

    def stop_polling(self) -> None:
        self._bot.stop()

    def _send_sync(self, text: str) -> bool:
        httpx = _get_httpx()
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        payload = {"chat_id": self._chat_id, "text": text}
        try:
            response = httpx.post(url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("telegram alert send failed", error=str(error))
            return False

    def format_event(self, event: AlertEvent) -> str:
        action = str(event.action).upper()
        if action == "BLOCKED":
            return "\n".join(
                [
                    f"🚨 BLOCKED | {event.severity.upper()}",
                    f"Agent: {event.agent_id or 'unknown'}",
                    f"Rule: {event.rule_id or 'n/a'}",
                    f"Time: {event.timestamp}",
                    f'Pattern: "{event.pattern or ""}"',
                ]
            )
        if action == "BUDGET_EXCEEDED":
            metadata = event.metadata if isinstance(event.metadata, dict) else {}
            spent = float(metadata.get("spent_usd", metadata.get("spent", 0.0)) or 0.0)
            limit = float(metadata.get("limit_usd", metadata.get("limit", 0.0)) or 0.0)
            rate = float(metadata.get("rate_per_hour", 0.0) or 0.0)
            projected = float(metadata.get("projected_24h", 0.0) or 0.0)
            eta = str(metadata.get("eta", "n/a"))
            return "\n".join(
                [
                    "💸 BUDGET WARNING",
                    f"Spent: ${spent:.2f} / ${limit:.2f}",
                    f"Rate: ${rate:.2f}/hour",
                    f"Projected: ${projected:.2f} in {eta}",
                ]
            )
        return f"[{event.severity.upper()}] {event.action}: {event.description}"

    def send(self, event: AlertEvent) -> bool:
        return self._send_sync(self.format_event(event))


class TelegramNotifier:
    """Send Orchesis alerts to Telegram via Bot API."""

    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        notify_on: list[str] | None = None,
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._notify_on = [item.upper() for item in (notify_on or DEFAULT_NOTIFY_ON)]
        self._logger = StructuredLogger("telegram_notifier")

    def format_deny(self, event: DecisionEvent) -> str:
        """Format DENY event as Telegram MarkdownV2 message."""
        reason = event.reasons[0] if event.reasons else "Denied by policy"
        lines = [
            "🚫 *Agent Blocked*",
            f"Agent: `{_escape_markdown_v2(event.agent_id)}`",
            f"Tool: `{_escape_markdown_v2(event.tool)}`",
            f"Reason: {_escape_markdown_v2(reason)}",
            f"Policy: `{_escape_markdown_v2(event.policy_version[:12])}`",
        ]
        return "\n".join(lines)

    def send(self, text: str) -> bool:
        """Send message to Telegram Bot API; fail-silent on errors."""
        httpx = _get_httpx()
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
        }
        try:
            response = httpx.post(url, json=payload, timeout=5.0)
            response.raise_for_status()
            return True
        except Exception as error:  # noqa: BLE001
            self._logger.warn("telegram send failed", error=str(error))
            return False

    def emit(self, event: DecisionEvent) -> None:
        """EventEmitter-compatible interface."""
        if event.decision == "DENY" and "DENY" in self._notify_on:
            self.send(self.format_deny(event))
            return
        if "ANOMALY" in self._notify_on and any(reason.startswith("anomaly:") for reason in event.reasons):
            self.send(_escape_markdown_v2("; ".join(event.reasons)))


class TelegramEmitter:
    """EventBus adapter for Telegram notifications."""

    def __init__(self, notifier: TelegramNotifier) -> None:
        self._notifier = notifier

    def emit(self, event: DecisionEvent) -> None:
        """Forward event to notifier with built-in filtering."""
        self._notifier.emit(event)
