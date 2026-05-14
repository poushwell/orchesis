/**
 * MCP Security Scanner Engine
 * Analyzes MCP configuration JSON for security issues.
 * Returns a score 0-100 and list of findings.
 */

(function initMCPSecurityScanner(globalScope) {
  const SEVERITY = {
    CRITICAL: { level: 4, label: "CRITICAL", color: "#dc2626", deduction: 25 },
    HIGH: { level: 3, label: "HIGH", color: "#ea580c", deduction: 15 },
    MEDIUM: { level: 2, label: "MEDIUM", color: "#ca8a04", deduction: 8 },
    LOW: { level: 1, label: "LOW", color: "#2563eb", deduction: 3 },
    INFO: { level: 0, label: "INFO", color: "#6b7280", deduction: 0 },
  };

  class MCPSecurityScanner {
    constructor() {
      this.findings = [];
      this.score = 100;
      this.totalDeduction = 0;
      this.maxDeduction = 85;
    }

    scan(configText) {
      this.findings = [];
      this.score = 100;
      this.totalDeduction = 0;

      let config;
      try {
        config = JSON.parse(configText);
      } catch (error) {
        this.addFinding(
          SEVERITY.CRITICAL,
          "Invalid JSON",
          `Config is not valid JSON: ${error.message}`,
          "Fix the JSON syntax before proceeding."
        );
        this.score = 0;
        return this.getResult();
      }

      this.checkServerTransport(config);
      this.checkServerCount(config);
      this.checkCommandInjection(config);
      this.checkEnvironmentVariables(config);
      this.checkSensitiveKeys(config);
      this.checkNetworkExposure(config);
      this.checkToolPermissions(config);
      this.checkKnownVulnerableServers(config);
      this.checkPathTraversal(config);
      this.checkShellExecution(config);
      this.checkNoTLS(config);
      this.checkWildcardPermissions(config);
      this.checkStaleServers(config);
      this.checkMissingDescriptions(config);
      this.checkDangerousDefaults(config);

      this.score = Math.max(0, this.score);
      return this.getResult();
    }

    addFinding(severity, title, description, remediation) {
      this.findings.push({ severity, title, description, remediation });
      const remaining = Math.max(0, this.maxDeduction - this.totalDeduction);
      const deduction = Math.min(severity.deduction, remaining);
      this.totalDeduction += deduction;
      this.score -= deduction;
    }

    getResult() {
      const finalScore = Math.max(0, Math.round(this.score));
      return {
        score: finalScore,
        grade: this.getGrade(finalScore),
        findings: this.findings.sort((a, b) => b.severity.level - a.severity.level),
        summary: this.getSummary(),
        scannedAt: new Date().toISOString(),
      };
    }

    getGrade(score) {
      if (score >= 90) return { letter: "A", color: "#16a34a", label: "Excellent" };
      if (score >= 75) return { letter: "B", color: "#65a30d", label: "Good" };
      if (score >= 55) return { letter: "C", color: "#ca8a04", label: "Needs Improvement" };
      if (score >= 35) return { letter: "D", color: "#ea580c", label: "Poor" };
      return { letter: "F", color: "#dc2626", label: "Critical Risk" };
    }

    getSummary() {
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      this.findings.forEach((finding) => {
        counts[finding.severity.label] += 1;
      });
      return counts;
    }

    checkServerTransport(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const transport = server.transport || server.type || "unknown";
        if (transport === "sse" || transport === "http" || transport === "streamable-http") {
          const url = server.url || server.baseUrl || "";
          const isRemote = !url.includes("localhost") && !url.includes("127.0.0.1");
          if (url.startsWith("http://") && isRemote) {
            this.addFinding(
              SEVERITY.CRITICAL,
              `Server "${name}" uses unencrypted HTTP`,
              `Transport uses HTTP to remote host: ${url}. MCP traffic can be intercepted in transit.`,
              "Switch to HTTPS or use stdio transport for local servers."
            );
          }
          if (isRemote) {
            this.addFinding(
              SEVERITY.MEDIUM,
              `Server "${name}" connects to remote endpoint`,
              `Remote MCP server at ${url}. Remote operator can observe tool calls and outputs.`,
              "Use trusted endpoints and prefer local servers where possible."
            );
          }
        }
      }
    }

    checkServerCount(config) {
      const servers = this.getServers(config);
      const count = Object.keys(servers).length;
      if (count > 10) {
        this.addFinding(
          SEVERITY.MEDIUM,
          `High server count (${count})`,
          `${count} MCP servers configured. Every additional server increases attack surface.`,
          "Remove unused servers and consolidate where possible."
        );
      }
      if (count === 0) {
        this.addFinding(
          SEVERITY.INFO,
          "No servers configured",
          "Config has no MCP servers. There is no active MCP attack surface in this file.",
          "Add MCP server configurations if you want a full scan."
        );
      }
    }

    checkCommandInjection(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const cmd = server.command || "";
        const args = (server.args || []).join(" ");
        const full = `${cmd} ${args}`;
        if (/[;&|`$()]/.test(args)) {
          this.addFinding(
            SEVERITY.CRITICAL,
            `Server "${name}": shell metacharacters in args`,
            `Arguments contain shell special characters: ${args.slice(0, 120)}.`,
            "Remove shell metacharacters and pass explicit arguments instead."
          );
        }
        if (/\b(eval|exec|sh -c|bash -c|cmd \/c|powershell -command)\b/i.test(full)) {
          this.addFinding(
            SEVERITY.HIGH,
            `Server "${name}": dynamic code execution pattern`,
            `Command path uses dynamic shell execution semantics: "${full.slice(0, 140)}".`,
            "Invoke binaries directly rather than shell wrappers."
          );
        }
      }
    }

    checkEnvironmentVariables(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const env = server.env || {};
        for (const [key, value] of Object.entries(env)) {
          if (typeof value === "string" && value.length > 10) {
            if (/^(sk-|ghp_|gho_|github_pat_|AKIA|xox[bsp]-|glpat-|Bearer\s)/i.test(value)) {
              this.addFinding(
                SEVERITY.CRITICAL,
                `Server "${name}": hardcoded credential in env`,
                `Environment variable "${key}" appears to contain a secret value.`,
                "Move secrets to secure environment variables or secret manager references."
              );
            }
          }
          if (/(api_key|api_secret|token|password|secret|credential|auth)/i.test(key) && (!value || value === "")) {
            this.addFinding(
              SEVERITY.LOW,
              `Server "${name}": empty sensitive env var "${key}"`,
              `Sensitive-looking environment variable "${key}" is empty.`,
              "Ensure it is set securely outside this config."
            );
          }
        }
      }
    }

    checkSensitiveKeys(config) {
      const walk = (obj, path = "") => {
        if (typeof obj === "string") {
          const patterns = [
            { regex: /sk-[a-zA-Z0-9]{20,}/, name: "OpenAI API key" },
            { regex: /ghp_[a-zA-Z0-9]{20,}/, name: "GitHub token" },
            { regex: /AKIA[0-9A-Z]{16}/, name: "AWS access key" },
            { regex: /xox[bsp]-[a-zA-Z0-9-]+/, name: "Slack token" },
            { regex: /glpat-[a-zA-Z0-9_-]{20,}/, name: "GitLab token" },
            { regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, name: "JWT token" },
            { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, name: "Private key" },
          ];
          for (const { regex, name } of patterns) {
            if (regex.test(obj)) {
              this.addFinding(
                SEVERITY.CRITICAL,
                `Exposed ${name} in config`,
                `Detected probable ${name} at path "${path}".`,
                "Remove secrets from config and use secure secret injection."
              );
            }
          }
        } else if (obj && typeof obj === "object") {
          for (const [key, value] of Object.entries(obj)) {
            walk(value, path ? `${path}.${key}` : key);
          }
        }
      };
      walk(config);
    }

    checkNetworkExposure(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const args = (server.args || []).join(" ");
        if (/0\.0\.0\.0/.test(args)) {
          this.addFinding(
            SEVERITY.HIGH,
            `Server "${name}" binds to all interfaces`,
            "Server appears to expose on 0.0.0.0.",
            "Bind to 127.0.0.1 unless remote access is explicitly required."
          );
        }
        const portMatch = args.match(/--port\s+(\d+)|:(\d{2,5})/);
        if (portMatch) {
          const port = portMatch[1] || portMatch[2];
          this.addFinding(
            SEVERITY.LOW,
            `Server "${name}" exposes port ${port}`,
            `Port ${port} detected in arguments.`,
            "Validate firewall and binding scope."
          );
        }
      }
    }

    checkToolPermissions(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        if (!server.allowedTools && !server.disabledTools && !server.tools) {
          this.addFinding(
            SEVERITY.MEDIUM,
            `Server "${name}": no tool restrictions`,
            "No allow/deny list found for exposed tools.",
            "Define allowedTools and avoid unrestricted tool exposure."
          );
        }
      }
    }

    checkKnownVulnerableServers(config) {
      const knownIssues = {
        "mcp-server-fetch": { severity: SEVERITY.LOW, issue: "Can fetch arbitrary URLs (SSRF risk)." },
        "mcp-server-puppeteer": { severity: SEVERITY.MEDIUM, issue: "Browser automation can reach untrusted content." },
        "mcp-server-filesystem": { severity: SEVERITY.MEDIUM, issue: "Filesystem access is high-risk without path restrictions." },
        "mcp-server-shell": { severity: SEVERITY.HIGH, issue: "Arbitrary shell execution capability." },
        "mcp-server-everything": { severity: SEVERITY.HIGH, issue: "Overprivileged package with broad capability surface." },
      };
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const cmd = server.command || "";
        const args = (server.args || []).join(" ");
        const haystack = `${cmd} ${args} ${name}`.toLowerCase();
        for (const [pkg, info] of Object.entries(knownIssues)) {
          if (haystack.includes(pkg.toLowerCase())) {
            this.addFinding(
              info.severity,
              `Server "${name}" uses ${pkg}`,
              info.issue,
              "Keep only if required, pin version, and apply strict runtime restrictions."
            );
          }
        }
      }
    }

    checkPathTraversal(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        const args = (server.args || []).join(" ");
        if (/\.\.\/|\.\.\\/.test(args)) {
          this.addFinding(
            SEVERITY.HIGH,
            `Server "${name}": path traversal in args`,
            `Arguments include traversal markers: "${args.slice(0, 120)}".`,
            "Use canonical absolute paths and remove traversal segments."
          );
        }
      }
    }

    checkShellExecution(config) {
      const servers = this.getServers(config);
      const dangerous = ["bash", "sh", "cmd", "powershell", "pwsh", "zsh"];
      for (const [name, server] of Object.entries(servers)) {
        const cmd = (server.command || "").toLowerCase();
        if (dangerous.some((d) => cmd === d || cmd.endsWith(`/${d}`) || cmd.endsWith(`\\${d}`))) {
          this.addFinding(
            SEVERITY.HIGH,
            `Server "${name}": runs via shell interpreter`,
            `Command "${server.command}" is a shell interpreter.`,
            "Prefer direct binary invocation over shell interpreters."
          );
        }
      }
    }

    checkNoTLS(config) {
      const text = JSON.stringify(config).toLowerCase();
      if (
        text.includes('"verify":false') ||
        text.includes('"verify": false') ||
        text.includes('"tls":false') ||
        text.includes('"tls": false') ||
        text.includes('"ssl":false') ||
        text.includes('"ssl": false') ||
        text.includes('"insecure":true') ||
        text.includes('"insecure": true')
      ) {
        this.addFinding(
          SEVERITY.HIGH,
          "TLS/SSL verification disabled",
          "Detected insecure TLS flags that can allow man-in-the-middle interception.",
          "Enable strict certificate verification."
        );
      }
    }

    checkWildcardPermissions(config) {
      const text = JSON.stringify(config);
      if (/"allowedTools"\s*:\s*\[\s*"\*"\s*\]/.test(text) || /"tools"\s*:\s*\[\s*"\*"\s*\]/.test(text)) {
        this.addFinding(
          SEVERITY.MEDIUM,
          "Wildcard tool permissions",
          'Wildcard "*" grants broad tool access.',
          "Replace wildcard with explicit minimal tool allowlist."
        );
      }
      if (/"allowedDirectories"\s*:\s*\[\s*"\/"\s*\]/.test(text)) {
        this.addFinding(
          SEVERITY.HIGH,
          "Root filesystem access",
          'Server appears to grant access to root directory "/".',
          "Restrict filesystem access to minimal required directories."
        );
      }
    }

    checkStaleServers(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        if (server.disabled === true) {
          this.addFinding(
            SEVERITY.LOW,
            `Server "${name}" is disabled but still present`,
            "Disabled servers increase configuration complexity and risk accidental re-enable.",
            "Remove stale disabled entries."
          );
        }
      }
    }

    checkMissingDescriptions(config) {
      const servers = this.getServers(config);
      const names = Object.keys(servers);
      let missing = 0;
      for (const server of Object.values(servers)) {
        if (!server.description && !(server.metadata && server.metadata.description)) {
          missing += 1;
        }
      }
      if (names.length > 0 && missing > 0) {
        this.addFinding(
          SEVERITY.INFO,
          `${missing} server(s) without descriptions`,
          "Missing descriptions make security reviews harder and slower.",
          "Document each server purpose and trust assumptions."
        );
      }
    }

    checkDangerousDefaults(config) {
      const servers = this.getServers(config);
      for (const [name, server] of Object.entries(servers)) {
        if (server.command === "npx" && !(server.args || []).some((arg) => /@[\w.-]+/.test(arg))) {
          this.addFinding(
            SEVERITY.MEDIUM,
            `Server "${name}": npx without version pinning`,
            "npx package version is not pinned.",
            "Pin exact package version, e.g. package@1.2.3."
          );
        }
        if ((server.command === "uvx" || server.command === "pipx") && !(server.args || []).some((arg) => arg.includes("=="))) {
          this.addFinding(
            SEVERITY.MEDIUM,
            `Server "${name}": ${server.command} without version pinning`,
            `${server.command} dependency is not pinned with ==version.`,
            "Pin exact dependency versions."
          );
        }
      }
    }

    getServers(config) {
      const asObject = config.mcpServers || config.servers || config["mcp-servers"] || config.mcptools || {};
      if (Array.isArray(asObject)) {
        const mapped = {};
        asObject.forEach((item, index) => {
          if (item && typeof item === "object") {
            const name = item.name || `server_${index + 1}`;
            mapped[name] = item;
          }
        });
        return mapped;
      }
      if (!asObject || typeof asObject !== "object") {
        return {};
      }
      return asObject;
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { MCPSecurityScanner, SEVERITY };
  }
  globalScope.MCPSecurityScanner = MCPSecurityScanner;
  globalScope.MCP_SEVERITY = SEVERITY;
})(typeof window !== "undefined" ? window : globalThis);
