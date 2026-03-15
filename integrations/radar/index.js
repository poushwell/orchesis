#!/usr/bin/env node
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");

const PORT = 8081;
const ORCHESIS_URL = "http://localhost:8080/api/v1/overwatch";
const HTML_PATH = path.join(__dirname, "radar.html");

const DEMO_DATA = {
  demo_mode: true,
  summary: {
    active_agents: 5,
    total_cost_day_usd: 18.42,
    threats_blocked: 1
  },
  agents: [
    {
      agent_id: "main",
      role: "orchestrator",
      status: "working",
      security_grade: "A+",
      current_task: "Coordinating worker fleet",
      model: "gpt-4o",
      requests_today: 980,
      cost_day_usd: 7.8,
      threats_today: 0
    },
    {
      agent_id: "research_01",
      role: "worker",
      status: "working",
      security_grade: "A+",
      current_task: "Researching source material",
      model: "claude-sonnet-4-20250514",
      requests_today: 720,
      cost_day_usd: 4.3,
      threats_today: 0
    },
    {
      agent_id: "coding_02",
      role: "worker",
      status: "idle",
      security_grade: "A",
      current_task: "Idle",
      model: "gpt-4o-mini",
      requests_today: 340,
      cost_day_usd: 1.6,
      threats_today: 0
    },
    {
      agent_id: "qa_03",
      role: "worker",
      status: "error",
      security_grade: "B+",
      current_task: "Regression suite retry",
      model: "claude-haiku-4-5-20251001",
      requests_today: 490,
      cost_day_usd: 2.4,
      threats_today: 1
    },
    {
      agent_id: "marketing_04",
      role: "worker",
      status: "working",
      security_grade: "A",
      current_task: "Drafting campaign copy",
      model: "gpt-4o-mini",
      requests_today: 260,
      cost_day_usd: 2.32,
      threats_today: 0
    }
  ]
};

function openBrowser(url) {
  const platform = process.platform;
  const command =
    platform === "win32"
      ? `start "" "${url}"`
      : platform === "darwin"
        ? `open "${url}"`
        : `xdg-open "${url}"`;
  childProcess.exec(command, () => {});
}

function readRadarHtml() {
  return fs.readFileSync(HTML_PATH, "utf8");
}

function fetchOverwatch(callback) {
  const req = http.get(ORCHESIS_URL, { timeout: 1500 }, (res) => {
    let body = "";
    res.setEncoding("utf8");
    res.on("data", (chunk) => {
      body += chunk;
    });
    res.on("end", () => {
      if (res.statusCode !== 200) {
        callback(DEMO_DATA);
        return;
      }
      try {
        const parsed = JSON.parse(body);
        if (parsed && typeof parsed === "object") {
          parsed.demo_mode = false;
          callback(parsed);
          return;
        }
      } catch (_err) {}
      callback(DEMO_DATA);
    });
  });

  req.on("timeout", () => {
    req.destroy(new Error("timeout"));
  });
  req.on("error", () => {
    callback(DEMO_DATA);
  });
}

function sendJson(res, payload) {
  const data = JSON.stringify(payload);
  res.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(data)
  });
  res.end(data);
}

const server = http.createServer((req, res) => {
  const url = req.url || "/";
  if (url === "/") {
    const html = readRadarHtml();
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    res.end(html);
    return;
  }

  if (url === "/api/overwatch") {
    fetchOverwatch((payload) => {
      sendJson(res, payload);
    });
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, "127.0.0.1", () => {
  const url = `http://localhost:${PORT}`;
  process.stdout.write(`orchesis-radar running at ${url}\n`);
  openBrowser(url);
});
