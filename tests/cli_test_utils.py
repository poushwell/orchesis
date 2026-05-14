from __future__ import annotations

import contextlib
import io
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class InvokeResult:
    exit_code: int
    output: str
    stdout: str
    stderr: str
    exception: Exception | None = None


class CliRunner:
    """Minimal argparse-compatible test runner replacement."""

    def __init__(self, catch_exceptions: bool = True) -> None:
        self.catch_exceptions = catch_exceptions

    @contextlib.contextmanager
    def isolated_filesystem(self):
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                yield temp_dir
            finally:
                os.chdir(original_cwd)

    def invoke(
        self,
        cli: Any,
        args: list[str] | tuple[str, ...] | None = None,
        input: str | None = None,
        env: dict[str, str | None] | None = None,
        catch_exceptions: bool | None = None,
        **_extra: Any,
    ) -> InvokeResult:
        argv = list(args or [])
        out_buffer = io.StringIO()
        err_buffer = io.StringIO()
        stdin_backup = os.sys.stdin
        env_backup = os.environ.copy()
        should_catch = self.catch_exceptions if catch_exceptions is None else catch_exceptions
        exception: Exception | None = None
        exit_code = 0
        try:
            if env is not None:
                for key, value in env.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
            os.sys.stdin = io.StringIO(input or "")
            with contextlib.redirect_stdout(out_buffer), contextlib.redirect_stderr(err_buffer):
                try:
                    if hasattr(cli, "main") and callable(getattr(cli, "main")):
                        result = cli.main(
                            args=argv,
                            prog_name=getattr(cli, "name", None) or "orchesis",
                            standalone_mode=False,
                        )
                    else:
                        result = cli(argv)
                    if isinstance(result, int):
                        exit_code = int(result)
                except SystemExit as exc:
                    code = exc.code
                    exit_code = int(code) if isinstance(code, int) else 1
                except Exception as exc:  # noqa: BLE001
                    if not should_catch:
                        raise
                    exception = exc
                    message = str(exc).strip()
                    if message:
                        print(message, file=err_buffer)
                    exit_code = 1
        finally:
            os.sys.stdin = stdin_backup
            os.environ.clear()
            os.environ.update(env_backup)

        stdout = out_buffer.getvalue()
        stderr = err_buffer.getvalue()
        return InvokeResult(
            exit_code=exit_code,
            output=stdout + stderr,
            stdout=stdout,
            stderr=stderr,
            exception=exception,
        )
