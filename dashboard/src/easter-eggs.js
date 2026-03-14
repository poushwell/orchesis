import { applyTheme } from "./themes";

const KONAMI = [
  "ArrowUp",
  "ArrowUp",
  "ArrowDown",
  "ArrowDown",
  "ArrowLeft",
  "ArrowRight",
  "ArrowLeft",
  "ArrowRight",
  "b",
  "a"
];

export function initEasterEggs(onThemeChange) {
  let konamiPos = 0;
  let typed = "";
  let typedTimer = null;

  function setTheme(theme) {
    const actual = applyTheme(theme);
    if (typeof onThemeChange === "function") {
      onThemeChange(actual);
    }
  }

  function deactivate() {
    setTheme("default");
  }

  function onKeydown(event) {
    const tag = event.target?.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA") return;

    if (event.key === "Escape") {
      deactivate();
      return;
    }

    if (event.key === KONAMI[konamiPos]) {
      konamiPos += 1;
      if (konamiPos === KONAMI.length) {
        konamiPos = 0;
        setTheme("matrix");
      }
    } else {
      konamiPos = event.key === KONAMI[0] ? 1 : 0;
    }

    if (event.key.length === 1) {
      typed = (typed + event.key.toLowerCase()).slice(-10);
      if (typedTimer) window.clearTimeout(typedTimer);
      typedTimer = window.setTimeout(() => {
        typed = "";
      }, 3000);
      const text = typed;
      if (text.endsWith("help")) {
        setTheme("dos");
      }
      if (text.endsWith("sputnik")) {
        setTheme("ussr");
      }
      if (text.endsWith("exit")) {
        deactivate();
      }
    }
  }

  function onStorage(event) {
    if (event.key === "orchesis_theme" && typeof event.newValue === "string") {
      const value = event.newValue;
      const theme = value === "matrix" || value === "dos" || value === "ussr" ? value : "default";
      applyTheme(theme);
      if (typeof onThemeChange === "function") {
        onThemeChange(theme);
      }
    }
  }

  window.addEventListener("keydown", onKeydown);
  window.addEventListener("storage", onStorage);
  window.orchesis = { hack: () => setTheme("matrix") };

  return () => {
    window.removeEventListener("keydown", onKeydown);
    window.removeEventListener("storage", onStorage);
    if (typedTimer) window.clearTimeout(typedTimer);
  };
}
