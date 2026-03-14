import { useEffect, useMemo, useState } from "react";

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

export function useApiPolling(tab) {
  const [data, setData] = useState({
    overview: null,
    stats: null,
    agents: null,
    sessions: null,
    threats: null,
    threatStats: null,
    compliance: null
  });
  const [connected, setConnected] = useState(true);

  const intervalMs = useMemo(() => {
    if (tab === "Shield") return 2500;
    if (tab === "Threats") return 2000;
    return 5000;
  }, [tab]);

  useEffect(() => {
    let active = true;
    let timer;

    async function load() {
      try {
        const [overview, stats, agents, sessions, threats, threatStats, compliance] = await Promise.all([
          fetchJson("/api/dashboard/overview").catch(() => null),
          fetchJson("/stats").catch(() => null),
          fetchJson("/api/dashboard/agents").catch(() => null),
          fetchJson("/api/sessions").catch(() => null),
          fetchJson("/api/threats").catch(() => null),
          fetchJson("/api/threats/stats").catch(() => null),
          fetchJson("/api/compliance/summary").catch(() => null)
        ]);
        if (!active) return;
        setData({ overview, stats, agents, sessions, threats, threatStats, compliance });
        setConnected(true);
      } catch (_err) {
        if (!active) return;
        setConnected(false);
      }
    }

    load();
    timer = window.setInterval(load, intervalMs);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [intervalMs]);

  return { data, connected };
}
