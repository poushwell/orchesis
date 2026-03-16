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
    monkeypatch.setattr("orchesis.cli.time.sleep", lambda *_args, **_kwargs: None)
    runner = CliRunner()
    result = runner.invoke(main, ["launch", "aider"])
    assert result.exit_code == 0
    assert len(commands) >= 2
    assert commands[1] == ["aider", "--openai-api-base", "http://localhost:8080/v1"]


def test_launch_cleanup_on_exit(monkeypatch) -> None:  # noqa: ANN001
    created: list[_FakeProcess] = []

    def _fake_popen(cmd, *args, **kwargs):  # noqa: ANN001
        _ = args, kwargs
        process = _FakeProcess(list(cmd))
        created.append(process)
        return process

    monkeypatch.setattr("orchesis.cli.subprocess.Popen", _fake_popen)
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
