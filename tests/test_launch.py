from __future__ import annotations

from tests.cli_test_utils import CliRunner

from orchesis.cli import main


class _FakeProcess:
    def __init__(self, command: list[str], return_code: int = 0) -> None:
        self.command = list(command)
        self.return_code = int(return_code)
        self.terminated = False
        self.killed = False
        self.wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        _ = timeout
        self.wait_calls += 1
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def test_launch_starts_proxy(monkeypatch) -> None:  # noqa: ANN001
    commands: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        commands.append(list(cmd))
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        "orchesis.cli._get_proxy_stats",
        lambda *_args, **_kwargs: {"requests": 0, "blocked": 0, "cost_today": 0.0},
    )
    monkeypatch.setattr("orchesis.cli.time.sleep", lambda *_args, **_kwargs: None)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "openclaw"])
    assert result.exit_code == 0
    assert len(commands) >= 1
    assert commands[0][:4] == ["python", "-m", "orchesis", "proxy"] or commands[0][1:4] == [
        "-m",
        "orchesis",
        "proxy",
    ]


def test_launch_connects_agent(monkeypatch) -> None:  # noqa: ANN001
    commands: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        commands.append(list(cmd))
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        "orchesis.cli._get_proxy_stats",
        lambda *_args, **_kwargs: {"requests": 0, "blocked": 0, "cost_today": 0.0},
    )
    monkeypatch.setattr("orchesis.cli.time.sleep", lambda *_args, **_kwargs: None)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "aider"])
    assert result.exit_code == 0
    assert len(commands) >= 2
    assert commands[1] == ["aider", "--openai-api-base", "http://localhost:8080/v1"]


def test_launch_continue_agent(monkeypatch) -> None:  # noqa: ANN001
    commands: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        commands.append(list(cmd))
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("orchesis.cli._get_proxy_stats", lambda *_args, **_kwargs: {"requests": 0, "blocked": 0, "cost_today": 0.0})
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "continue"])
    assert result.exit_code == 0
    assert len(commands) >= 2
    assert commands[1] == ["continue", "--base-url", "http://localhost:8080/v1"]


def test_launch_cleanup_on_exit(monkeypatch) -> None:  # noqa: ANN001
    created: list[_FakeProcess] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        process = _FakeProcess(list(cmd))
        created.append(process)
        return process

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        "orchesis.cli._get_proxy_stats",
        lambda *_args, **_kwargs: {"requests": 0, "blocked": 0, "cost_today": 0.0},
    )
    monkeypatch.setattr("orchesis.cli.time.sleep", lambda *_args, **_kwargs: None)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "codex"])
    assert result.exit_code == 0
    assert len(created) >= 2
    proxy_process = created[0]
    assert proxy_process.terminated is True


def test_launch_invalid_agent() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "unknown-agent"])
    assert result.exit_code != 0
    assert "not one of" in result.output.lower() or "invalid choice" in result.output.lower()


def test_launch_cursor_sets_env_var(monkeypatch) -> None:  # noqa: ANN001
    popen_calls: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        popen_calls.append(list(cmd))
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "cursor"])
    assert result.exit_code == 0
    assert "Set OPENAI_API_BASE for Cursor IDE" in result.output
    assert "Restart Cursor to apply proxy settings" in result.output
    assert popen_calls == []


def test_launch_proxy_health_check(monkeypatch) -> None:  # noqa: ANN001
    calls: list[list[str]] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        calls.append(list(cmd))
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: False)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "openclaw"])
    assert result.exit_code != 0
    assert len(calls) == 1
    assert "health check" in result.output.lower()


def test_launch_prints_dashboard_url(monkeypatch) -> None:  # noqa: ANN001
    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        return _FakeProcess(list(cmd))

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("orchesis.cli._get_proxy_stats", lambda *_args, **_kwargs: {"requests": 0, "blocked": 0, "cost_today": 0.0})
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "openclaw"])
    assert result.exit_code == 0
    assert "Dashboard: http://localhost:8080/dashboard" in result.output


def test_launch_session_summary_on_exit(monkeypatch) -> None:  # noqa: ANN001
    popen_calls = {"count": 0}

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        popen_calls["count"] += 1
        return _FakeProcess(list(cmd))

    stats_values = iter(
        [
            {"requests": 10, "blocked": 2, "cost_today": 1.0000},
            {"requests": 17, "blocked": 4, "cost_today": 1.2500},
        ]
    )

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("orchesis.cli._wait_for_proxy", lambda *_args, **_kwargs: True)
    monkeypatch.setattr("orchesis.cli._get_proxy_stats", lambda *_args, **_kwargs: next(stats_values))
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "codex"])
    assert result.exit_code == 0
    assert "── Session summary ──" in result.output
    assert "Requests intercepted: 7" in result.output
    assert "Threats blocked: 2" in result.output
    assert "Cost: $0.2500" in result.output
