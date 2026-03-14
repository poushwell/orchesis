export const THEMES = {
  default: {
    "--bg": "#0a0a0a",
    "--text": "#ffffff",
    "--accent": "#a855f7",
    "--green": "#00FF41",
    "--red": "#ef4444",
    "--border": "rgba(255,255,255,0.08)",
    "--card": "#111111",
    "--muted": "rgba(255,255,255,0.7)",
    "--cyan": "#22d3ee",
    "--orange": "#fb923c"
  },
  matrix: {
    "--bg": "#020b02",
    "--text": "#b6ffbf",
    "--accent": "#00ff41",
    "--green": "#00FF41",
    "--red": "#22c55e",
    "--border": "rgba(0,255,65,0.22)",
    "--card": "#031103",
    "--muted": "rgba(182,255,191,0.7)",
    "--cyan": "#00e5a0",
    "--orange": "#84cc16"
  },
  dos: {
    "--bg": "#06155a",
    "--text": "#b3d2ff",
    "--accent": "#60a5fa",
    "--green": "#38bdf8",
    "--red": "#f43f5e",
    "--border": "rgba(147,197,253,0.25)",
    "--card": "#0a1c79",
    "--muted": "rgba(179,210,255,0.7)",
    "--cyan": "#67e8f9",
    "--orange": "#93c5fd"
  },
  ussr: {
    "--bg": "#240606",
    "--text": "#ffe4d6",
    "--accent": "#ef4444",
    "--green": "#f59e0b",
    "--red": "#dc2626",
    "--border": "rgba(248,113,113,0.22)",
    "--card": "#3a0d0d",
    "--muted": "rgba(255,228,214,0.72)",
    "--cyan": "#f97316",
    "--orange": "#fb7185"
  }
};

export function applyTheme(themeName) {
  const target = THEMES[themeName] ? themeName : "default";
  const root = document.documentElement;
  const vars = THEMES[target];
  Object.entries(vars).forEach(([key, value]) => root.style.setProperty(key, value));
  localStorage.setItem("orchesis_theme", target);
  root.setAttribute("data-theme", target);
  return target;
}

export function getStoredTheme() {
  return localStorage.getItem("orchesis_theme") || "default";
}
