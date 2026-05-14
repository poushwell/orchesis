#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const VERSION = "0.1.0";
const SEVERITY_ORDER = { low: 1, medium: 2, high: 3, critical: 4 };
const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  gray: "\x1b[90m",
};

function printUsage() {
  console.log(
    [
      "Usage: orchesis-scan [options]",
      "",
      "Options:",
      "  --config <path>         Custom MCP config path",
      "  --format json           Output raw JSON",
      "  --min-severity <level>  Filter findings (critical/high/medium/low), default: low",
      "  --fail-on <level>       Exit 1 threshold (critical/high/medium/low), default: high",
      "  --version               Print version",
    ].join("\n")
  );
}

function normalizeSeverity(value, flagName) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!SEVERITY_ORDER[normalized]) {
    console.error(`Invalid ${flagName}: ${value}`);
    process.exit(2);
  }
  return normalized;
}

function parseArgs(argv) {
  const options = {
    config: null,
    format: "text",
    minSeverity: "low",
    failOn: "high",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--version") {
      console.log(VERSION);
      process.exit(0);
    }
    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    }
    if (arg === "--config") {
      options.config = argv[i + 1] || "";
      i += 1;
      continue;
    }
    if (arg === "--format") {
      const next = String(argv[i + 1] || "").trim().toLowerCase();
      if (next !== "json") {
        console.error("--format currently supports only: json");
        process.exit(2);
      }
      options.format = "json";
      i += 1;
      continue;
    }
    if (arg === "--min-severity") {
      options.minSeverity = normalizeSeverity(argv[i + 1], "--min-severity");
      i += 1;
      continue;
    }
    if (arg === "--fail-on") {
      options.failOn = normalizeSeverity(argv[i + 1], "--fail-on");
      i += 1;
      continue;
    }
    console.error(`Unknown argument: ${arg}`);
    printUsage();
    process.exit(2);
  }

  if (options.config !== null && !String(options.config).trim()) {
    console.error("--config requires a file path");
    process.exit(2);
  }
  return options;
}

function detectConfigs(customPath) {
  if (customPath) {
    return [path.resolve(customPath)];
  }

  const home = os.homedir();
  const candidates = [
    path.join(home, ".config", "claude", "claude_desktop_config.json"),
    path.join(home, ".cursor", "mcp.json"),
    path.join(process.cwd(), ".vscode", "mcp.json"),
    path.join(process.cwd(), ".claude", "mcp.json"),
  ];

  return candidates.filter((candidate) => fs.existsSync(candidate));
}

function runScan(configPath) {
  const commands = [
    { bin: "python3", args: ["-m", "orchesis", "scan", "--format", "json", configPath] },
    { bin: "python", args: ["-m", "orchesis", "scan", "--format", "json", configPath] },
  ];

  for (const cmd of commands) {
    const result = spawnSync(cmd.bin, cmd.args, { encoding: "utf8" });
    if (result.error && result.error.code === "ENOENT") {
      continue;
    }
    if (result.status !== 0) {
      throw new Error(
        `Scanner command failed (${cmd.bin}): ${result.stderr || result.stdout || "unknown error"}`
      );
    }
    try {
      return JSON.parse(result.stdout);
    } catch (_err) {
      throw new Error(`Scanner did not return valid JSON for ${configPath}`);
    }
  }

  throw new Error("Unable to find python3 or python in PATH");
}

function colorForSeverity(severity) {
  const key = String(severity || "").toLowerCase();
  if (key === "critical") return COLORS.red;
  if (key === "high") return COLORS.yellow;
  if (key === "medium") return COLORS.blue;
  return COLORS.gray;
}

function severityMeetsThreshold(severity, threshold) {
  const left = SEVERITY_ORDER[String(severity || "").toLowerCase()] || 0;
  const right = SEVERITY_ORDER[threshold] || 0;
  return left >= right;
}

function normalizeScanPayload(payload, sourcePath) {
  if (Array.isArray(payload)) {
    if (payload.length === 0) {
      return { target: sourcePath, findings: [], risk_score: 0, summary: "No findings detected." };
    }
    return payload[0];
  }
  if (payload && typeof payload === "object") {
    return payload;
  }
  return { target: sourcePath, findings: [], risk_score: 0, summary: "No findings detected." };
}

function printTextOutput(results, minSeverity) {
  for (const result of results) {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const filtered = findings.filter((item) => severityMeetsThreshold(item.severity, minSeverity));
    console.log(`\nTarget: ${result.target || "unknown"}`);
    console.log(`Risk Score: ${result.risk_score || 0}/100`);
    if (filtered.length === 0) {
      console.log("No findings at selected threshold.");
      continue;
    }

    for (const finding of filtered) {
      const sev = String(finding.severity || "low").toUpperCase();
      const color = colorForSeverity(sev);
      const line = `[${sev}] ${finding.description || "Finding"} (${finding.location || "unknown"})`;
      console.log(`${color}${line}${COLORS.reset}`);
    }
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  const configs = detectConfigs(options.config);

  if (configs.length === 0) {
    console.error(
      "No MCP configuration found. Checked ~/.config/claude/claude_desktop_config.json, ~/.cursor/mcp.json, ./.vscode/mcp.json, ./.claude/mcp.json"
    );
    process.exit(2);
  }

  const results = [];
  for (const configPath of configs) {
    if (!fs.existsSync(configPath)) {
      continue;
    }
    const payload = runScan(configPath);
    results.push(normalizeScanPayload(payload, configPath));
  }

  if (options.format === "json") {
    const jsonOutput = results.length === 1 ? results[0] : results;
    console.log(JSON.stringify(jsonOutput, null, 2));
  } else {
    printTextOutput(results, options.minSeverity);
  }

  const failThreshold = options.failOn;
  const violations = results.flatMap((result) =>
    (Array.isArray(result.findings) ? result.findings : []).filter((item) =>
      severityMeetsThreshold(item.severity, failThreshold)
    )
  );
  process.exit(violations.length > 0 ? 1 : 0);
}

main();
