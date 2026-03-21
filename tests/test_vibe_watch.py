from __future__ import annotations

import json
import inspect
import time
from pathlib import Path
from unittest.mock import MagicMock

import orchesis.vibe_watch
from orchesis.vibe_watch import DEFAULT_EXCLUDES, DEFAULT_EXTENSIONS, AuditResult, VibeWatcher, WatchEvent


def _touch(path: Path, content: str = "print('ok')\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_watcher_init(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    assert watcher.interval == 2.0
    assert watcher.extensions == DEFAULT_EXTENSIONS
    assert watcher.exclude_patterns == DEFAULT_EXCLUDES


def test_watcher_custom_extensions(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path), extensions={".py"})
    _touch(tmp_path / "a.py")
    _touch(tmp_path / "a.js", "console.log('x')\n")
    scanned = watcher._scan_files()  # noqa: SLF001
    assert any(key.endswith("a.py") for key in scanned)
    assert not any(key.endswith("a.js") for key in scanned)


def test_watcher_excludes(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    for name in ("__pycache__", "node_modules", ".git"):
        assert name in watcher.exclude_patterns


def test_detect_new_file(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    watcher._file_mtimes = watcher._scan_files()  # noqa: SLF001
    _touch(tmp_path / "new.py")
    current = watcher._scan_files()  # noqa: SLF001
    events = watcher._detect_changes(current)  # noqa: SLF001
    assert any(event.event_type == "created" and event.filepath.endswith("new.py") for event in events)


def test_detect_modified_file(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    path = tmp_path / "m.py"
    _touch(path, "a=1\n")
    watcher._file_mtimes = watcher._scan_files()  # noqa: SLF001
    current_mtime = watcher._file_mtimes[str(path.resolve())]  # noqa: SLF001
    path.write_text("a=2\n", encoding="utf-8")
    new_mtime = current_mtime + 2.0
    path.touch()
    Path(path).stat()
    import os

    os.utime(path, (new_mtime, new_mtime))
    current = watcher._scan_files()  # noqa: SLF001
    events = watcher._detect_changes(current)  # noqa: SLF001
    assert any(event.event_type == "modified" and event.filepath.endswith("m.py") for event in events)


def test_detect_deleted_file(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    path = tmp_path / "gone.py"
    _touch(path)
    watcher._file_mtimes = watcher._scan_files()  # noqa: SLF001
    path.unlink()
    current = watcher._scan_files()  # noqa: SLF001
    events = watcher._detect_changes(current)  # noqa: SLF001
    assert any(event.event_type == "deleted" and event.filepath.endswith("gone.py") for event in events)


def test_ignore_excluded_dir(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    _touch(tmp_path / "node_modules" / "pkg" / "bad.js", "console.log('x')\n")
    scanned = watcher._scan_files()  # noqa: SLF001
    assert not any("node_modules" in key for key in scanned)


def test_ignore_wrong_extension(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    _touch(tmp_path / "a.txt", "x\n")
    _touch(tmp_path / "b.csv", "x\n")
    scanned = watcher._scan_files()  # noqa: SLF001
    assert scanned == {}


def test_nested_directory(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    _touch(tmp_path / "src" / "utils" / "x.py")
    scanned = watcher._scan_files()  # noqa: SLF001
    assert any(key.endswith("src\\utils\\x.py") or key.endswith("src/utils/x.py") for key in scanned)


def test_debounce(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path))
    filepath = str((tmp_path / "debounce.py").resolve())
    assert watcher._should_debounce(filepath) is False  # noqa: SLF001
    assert watcher._should_debounce(filepath) is True  # noqa: SLF001


def test_stop_graceful(tmp_path: Path) -> None:
    watcher = VibeWatcher(str(tmp_path), interval=0.05)
    watcher.start(blocking=False)
    time.sleep(0.3)
    watcher.stop()
    assert watcher._stop_event.is_set()  # noqa: SLF001


def test_summary_on_stop(tmp_path: Path) -> None:
    _touch(tmp_path / "a.py")
    watcher = VibeWatcher(str(tmp_path), interval=0.05)
    watcher.start(blocking=False)
    time.sleep(0.2)
    watcher.stop()
    summary = watcher.get_summary()
    assert summary.files_watched >= 1
    assert summary.duration_seconds > 0
    assert "Files watched" in summary.format()


def test_json_output(tmp_path: Path) -> None:
    out = tmp_path / "watch.jsonl"
    watcher = VibeWatcher(str(tmp_path), output_jsonl=str(out))
    event = WatchEvent(event_type="modified", filepath=str((tmp_path / "a.py").resolve()), timestamp=time.time())
    result = AuditResult(filepath=event.filepath, issues=[{"severity": "high", "message": "x", "line": 1}], timestamp=time.time())
    watcher._write_jsonl(event, result)  # noqa: SLF001
    line = out.read_text(encoding="utf-8").strip()
    payload = json.loads(line)
    assert payload["event_type"] == "modified"
    assert isinstance(payload["issues"], list)


def test_callback_mode(tmp_path: Path) -> None:
    callback = MagicMock()
    watcher = VibeWatcher(str(tmp_path), on_change_callback=callback)
    path = str((tmp_path / "cb.py").resolve())
    event = WatchEvent(event_type="created", filepath=path, timestamp=time.time())
    watcher._run_audit = MagicMock(return_value=AuditResult(filepath=path, issues=[], timestamp=time.time()))  # type: ignore[method-assign]  # noqa: SLF001
    watcher._handle_event(event)  # noqa: SLF001
    callback.assert_called_once()


def test_vibe_watch_no_phantom_import() -> None:
    source = inspect.getsource(orchesis.vibe_watch)
    assert "vibe_code_audit" not in source
