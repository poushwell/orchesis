from __future__ import annotations

import os
import platform
import subprocess
import threading
import time
from typing import Any

try:
    import resource  # type: ignore
except Exception:  # pragma: no cover
    resource = None  # type: ignore

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


class MetricsCollector:
    """Collect basic RSS/CPU metrics during stress runs."""

    def __init__(self, proxy_pid: int | None = None, interval_seconds: float = 1.0) -> None:
        self._pid = int(proxy_pid) if proxy_pid else os.getpid()
        self._interval = max(0.2, float(interval_seconds))
        self._running = False
        self._thread: threading.Thread | None = None
        self._rss_samples: list[float] = []
        self._cpu_samples: list[float] = []
        self._start = 0.0
        self._cpu_prev_total = time.process_time()
        self._cpu_prev_wall = time.perf_counter()

    def start(self) -> None:
        self._running = True
        self._start = time.perf_counter()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> dict[str, Any]:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)

        duration = max(0.0, time.perf_counter() - self._start)
        rss_start = self._rss_samples[0] if self._rss_samples else 0.0
        rss_end = self._rss_samples[-1] if self._rss_samples else 0.0
        rss_peak = max(self._rss_samples) if self._rss_samples else 0.0
        cpu_avg = (sum(self._cpu_samples) / len(self._cpu_samples)) if self._cpu_samples else 0.0
        cpu_peak = max(self._cpu_samples) if self._cpu_samples else 0.0
        return {
            "rss_mb": {
                "start": round(rss_start, 3),
                "end": round(rss_end, 3),
                "peak": round(rss_peak, 3),
                "growth": round(rss_end - rss_start, 3),
            },
            "cpu_percent": {"avg": round(cpu_avg, 3), "peak": round(cpu_peak, 3)},
            "duration_seconds": round(duration, 3),
            "samples": len(self._rss_samples),
            "platform": platform.platform(),
            "python": platform.python_version(),
        }

    def _loop(self) -> None:
        while self._running:
            self._rss_samples.append(self.get_rss_mb(self._pid))
            self._cpu_samples.append(self._sample_cpu_percent())
            time.sleep(self._interval)

    def _sample_cpu_percent(self) -> float:
        if psutil is not None:
            try:
                proc = psutil.Process(self._pid)
                return float(proc.cpu_percent(interval=None))
            except Exception:
                pass
        if self._pid != os.getpid():
            return 0.0
        now_total = time.process_time()
        now_wall = time.perf_counter()
        delta_total = max(0.0, now_total - self._cpu_prev_total)
        delta_wall = max(1e-9, now_wall - self._cpu_prev_wall)
        self._cpu_prev_total = now_total
        self._cpu_prev_wall = now_wall
        return (delta_total / delta_wall) * 100.0

    @staticmethod
    def get_rss_mb(pid: int) -> float:
        if psutil is not None:
            try:
                return float(psutil.Process(pid).memory_info().rss) / (1024.0 * 1024.0)
            except Exception:
                pass

        if os.name == "nt":
            return MetricsCollector._rss_windows_tasklist(pid)

        # Linux /proc fallback for foreign pids.
        proc_path = f"/proc/{pid}/status"
        if os.path.exists(proc_path):
            try:
                with open(proc_path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        if line.startswith("VmRSS:"):
                            parts = line.split()
                            if len(parts) >= 2:
                                kb = float(parts[1])
                                return kb / 1024.0
            except Exception:
                pass

        # Unix current process fallback.
        if resource is not None and pid == os.getpid():
            try:
                value = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                # On macOS ru_maxrss is bytes, on Linux it is KB.
                if platform.system().lower() == "darwin":
                    return value / (1024.0 * 1024.0)
                return value / 1024.0
            except Exception:
                pass
        return 0.0

    @staticmethod
    def _rss_windows_tasklist(pid: int) -> float:
        try:
            cmd = ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]
            out = subprocess.check_output(cmd, text=True, encoding="utf-8", errors="replace")
            line = out.strip()
            if not line or "No tasks are running" in line:
                return 0.0
            cols = [item.strip().strip('"') for item in line.split('","')]
            if len(cols) < 5:
                return 0.0
            mem_text = cols[-1].replace(",", "").replace("K", "").replace("k", "").strip()
            kb = float(mem_text)
            return kb / 1024.0
        except Exception:
            return 0.0
