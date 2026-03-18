#!/usr/bin/env node

/**
 * HyConnect Policy Dashboard Launcher
 * Launches a web server and opens the policy testing dashboard
 */

import http from "node:http";
import { exec } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================
// CONFIGURATION
// ============================================
const ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
const ALGO_AES_256_GCM = 0x01;
const DASHBOARD_PORT = 16271;
const POLICY_SERVER_PORT = 16271;

let loggedIn = false;
let clients = [];

// ============================================
// ENCRYPTION FUNCTIONS
// ============================================

function encryptData(base64Data) {
  const algorithm = 'aes-256-gcm';
  const key = Buffer.from(ENCRYPTION_KEY, 'utf8');
  const ivLength = 12;
  
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  
  let encrypted = cipher.update(base64Data, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const authTag = cipher.getAuthTag();
  
  const algoIdBuf = Buffer.from([ALGO_AES_256_GCM]);
  const combined = Buffer.concat([algoIdBuf, iv, encrypted, authTag]);
  
  return combined.toString('base64');
}

function encodeBase64(obj) {
  const jsonStr = JSON.stringify(obj);
  const base64 = Buffer.from(jsonStr).toString("base64");
  const encrypted = encryptData(base64);
  
  console.log("=== ENCRYPTION DEBUG ===");
  console.log("Original JSON:", jsonStr);
  console.log("Base64 Encoded:", base64);
  console.log("AES-256-GCM Encrypted:", encrypted);
  console.log("=======================");
  
  return encrypted;
}

function getDecodedPolicy() {
  return loggedIn
    ? {
        DownloadRestrictions: 3,
        IncognitoModeAvailability: 1
      }
    : {};
}

function getPolicyPayload() {
  return {
    loginStatus: loggedIn ? 2 : 0,
    policydata: encodeBase64(getDecodedPolicy())
  };
}

function sendPolicy() {
  const payload = getPolicyPayload();
  const data = `data: ${JSON.stringify(payload)}\n\n`;

  clients.forEach(res => res.write(data));
  console.log("Policy sent to", clients.length, "client(s)");
}

// ============================================
// HTTP SERVER
// ============================================

const server = http.createServer((req, res) => {
  // CORS headers for local development
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Serve the dashboard HTML
  if (req.url === "/" || req.url === "/dashboard") {
    const htmlPath = path.join(__dirname, 'policyMaker.html');
    fs.readFile(htmlPath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Error loading dashboard");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(data);
    });
    return;
  }

  // Toggle login endpoint
  if (req.url === "/toggle") {
    loggedIn = !loggedIn;
    sendPolicy();
    res.writeHead(204);
    res.end();
    return;
  }

  // SSE policy stream endpoint
  if (req.url === "/streamPluginPolicy") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "Access-Control-Allow-Origin": "*"
    });

    clients.push(res);

    // Send current policy immediately
    const payload = getPolicyPayload();
    res.write(`data: ${JSON.stringify(payload)}\n\n`);

    req.on("close", () => {
      clients = clients.filter(c => c !== res);
      console.log("Client disconnected. Active clients:", clients.length);
    });
    return;
  }

  // API: Get current login status
  if (req.url === "/api/status") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      loggedIn,
      activeClients: clients.length,
      timestamp: new Date().toISOString()
    }));
    return;
  }

  // API: Set login status
  if (req.url.startsWith("/api/login/")) {
    const newStatus = req.url.endsWith("/true");
    loggedIn = newStatus;
    sendPolicy();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, loggedIn }));
    return;
  }

  // 404
  res.writeHead(404);
  res.end();
});

// ============================================
// START SERVER
// ============================================

server.listen(DASHBOARD_PORT, () => {
  const url = `http://localhost:${DASHBOARD_PORT}`;
  console.log("\n" + "=".repeat(60));
  console.log("🚀 HyConnect Policy Dashboard Server");
  console.log("=".repeat(60));
  console.log(`📊 Dashboard URL: ${url}`);
  console.log(`🔌 Policy Stream: ${url}/streamPluginPolicy`);
  console.log(`🔐 Encryption: AES-256-GCM`);
  console.log(`📝 Login Status: ${loggedIn ? "LOGGED IN" : "LOGGED OUT"}`);
  console.log("=".repeat(60) + "\n");

  // Auto-open browser
  const openCmd =
    process.platform === "darwin" ? `open ${url}` :
    process.platform === "win32" ? `start ${url}` :
    `xdg-open ${url}`;

  exec(openCmd, (error) => {
    if (error) {
      console.log(`\n⚠️  Could not auto-open browser. Please visit: ${url}\n`);
    } else {
      console.log("✅ Browser opened automatically\n");
    }
  });
});

// Graceful shutdown
function shutdown() {
  console.log('\n\n👋 Shutting down server...');
  
  // Close all SSE connections
  clients.forEach(client => {
    try {
      client.end();
    } catch (e) {
      // Ignore errors
    }
  });
  clients = [];
  
  // Close server
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
  
  // Force exit after 2 seconds if server doesn't close
  setTimeout(() => {
    console.log('⚠️  Forcing shutdown...');
    process.exit(0);
  }, 2000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
