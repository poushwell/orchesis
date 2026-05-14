#!/usr/bin/env node
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const VERSION = "0.1.0";
const SEVERITY_ORDER = ["low", "medium", "high", "critical"];
const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  bold: "\x1b[1m",
  yellow: "\x1b[33m",
  gray: "\x1b[90m",
};

function printUsage() {
  console.log(
    [
      "Usage: orchesis-scan [options]",
      "",
      "Options:",
      "  --config <path>         Custom MCP config path",
      "  --severity <level>      Filter findings by minimum severity (low/medium/high/critical)",
      "  --fix                   Print remediation for each finding",
      "  --output <path>         Save report as JSON file",
      "  --format json           Output raw JSON to stdout",
      "  --fail-on <level>       Exit 1 threshold (low/medium/high/critical), default: high",
      "  --version               Print version",
    ].join("\n")
  );
}

function normalizeSeverity(value, flagName) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!SEVERITY_ORDER.includes(normalized)) {
    console.error(`Invalid ${flagName}: ${value}`);
    process.exit(2);
  }
  return normalized;
}

function parseArgs(argv) {
  const options = {
    config: null,
    format: "text",
    severity: "low",
    failOn: "high",
    fix: false,
    output: null,
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
    if (arg === "--severity" || arg === "--min-severity") {
      options.severity = normalizeSeverity(argv[i + 1], arg);
      i += 1;
      continue;
    }
    if (arg === "--fail-on") {
      options.failOn = normalizeSeverity(argv[i + 1], "--fail-on");
      i += 1;
      continue;
    }
    if (arg === "--fix") {
      options.fix = true;
      continue;
    }
    if (arg === "--output") {
      options.output = argv[i + 1] || "";
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
  if (options.output !== null && !String(options.output).trim()) {
    console.error("--output requires a file path");
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
      throw new Error(`Scanner command failed (${cmd.bin}): ${result.stderr || result.stdout || "unknown error"}`);
    }
    try {
      return JSON.parse(result.stdout);
    } catch (_err) {
      throw new Error(`Scanner did not return valid JSON for ${configPath}`);
    }
  }
  throw new Error("Unable to find python3 or python in PATH");
}

function severityMeetsThreshold(severity, threshold) {
  const left = SEVERITY_ORDER.indexOf(String(severity || "").toLowerCase());
  const right = SEVERITY_ORDER.indexOf(String(threshold || "").toLowerCase());
  return left >= Math.max(0, right);
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

function remediationForFinding(finding) {
  if (finding && typeof finding.remediation === "string" && finding.remediation.trim()) {
    return finding.remediation.trim();
  }
  const desc = String((finding && finding.description) || "").toLowerCase();
  if (desc.includes("version")) return "Pin package version to an audited fixed version.";
  if (desc.includes("token") || desc.includes("key")) return "Rotate leaked credentials and move secrets to env or vault.";
  if (desc.includes("permission")) return "Reduce permissions to least privilege.";
  return "Review finding details and apply least-privilege, input validation, and version pinning.";
}

function colorizeSeverityLabel(severity) {
  const key = String(severity || "").toLowerCase();
  const label = key.toUpperCase();
  if (key === "critical") return `${COLORS.bold}${COLORS.red}${label}${COLORS.reset}`;
  if (key === "high") return `${COLORS.red}${label}${COLORS.reset}`;
  if (key === "medium") return `${COLORS.yellow}${label}${COLORS.reset}`;
  return `${COLORS.gray}${label}${COLORS.reset}`;
}

function computeSummary(filteredFindings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of filteredFindings) {
    const sev = String(finding.severity || "low").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, sev)) {
      summary[sev] += 1;
    }
  }
  return summary;
}

function printTextOutput(results, options) {
  const allFiltered = [];
  for (const result of results) {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const filtered = findings.filter((item) => severityMeetsThreshold(item.severity, options.severity));
    allFiltered.push(...filtered);
    console.log(`\nTarget: ${result.target || "unknown"}`);
    console.log(`Risk Score: ${result.risk_score || 0}/100`);
    if (filtered.length === 0) {
      console.log("No findings at selected threshold.");
      continue;
    }
    for (const finding of filtered) {
      const sev = String(finding.severity || "low").toLowerCase();
      const line = `⚠️ [${colorizeSeverityLabel(sev)}] ${finding.description || "Finding"} (${finding.location || "unknown"})`;
      console.log(line);
      if (options.fix) {
        console.log(`   🔧 Remediation: ${remediationForFinding(finding)}`);
      }
    }
  }
  const summary = computeSummary(allFiltered);
  console.log(`\nSummary: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium, ${summary.low} low`);
}

function loadMockResultsIfPresent() {
  const raw = process.env.ORCHESIS_SCAN_MOCK_JSON;
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    return [parsed];
  } catch (_err) {
    return null;
  }
}

function main() {
  const options = parseArgs(process.argv.slice(2));

  let results = [];
  const mocked = loadMockResultsIfPresent();
  if (mocked) {
    results = mocked.map((item, idx) => normalizeScanPayload(item, `mock-${idx + 1}`));
  } else {
    const configs = detectConfigs(options.config);
    if (configs.length === 0) {
      console.error("No MCP configuration found. Checked ~/.config/claude/claude_desktop_config.json, ~/.cursor/mcp.json, ./.vscode/mcp.json, ./.claude/mcp.json");
      process.exit(2);
    }
    for (const configPath of configs) {
      if (!fs.existsSync(configPath)) continue;
      const payload = runScan(configPath);
      results.push(normalizeScanPayload(payload, configPath));
    }
  }

  const normalizedResults = results.map((result) => {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    const filtered = findings.filter((item) => severityMeetsThreshold(item.severity, options.severity));
    return { ...result, findings: filtered };
  });

  if (options.output) {
    const outputPath = path.resolve(String(options.output));
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify({ results: normalizedResults }, null, 2), "utf8");
  }

  if (options.format === "json") {
    const jsonOutput = normalizedResults.length === 1 ? normalizedResults[0] : normalizedResults;
    console.log(JSON.stringify(jsonOutput, null, 2));
  } else {
    printTextOutput(normalizedResults, options);
  }

  const violations = normalizedResults.flatMap((result) =>
    (Array.isArray(result.findings) ? result.findings : []).filter((item) =>
      severityMeetsThreshold(item.severity, options.failOn)
    )
  );
  process.exit(violations.length > 0 ? 1 : 0);
}

if (require.main === module) {
  main();
}

module.exports = {
  SEVERITY_ORDER,
  parseArgs,
  severityMeetsThreshold,
  remediationForFinding,
  colorizeSeverityLabel,
  computeSummary,
};
