#!/usr/bin/env node

import http from "node:http";
import { exec } from "node:child_process";

const PORT = 8889;
const APP_URL = `http://127.0.0.1:${PORT}`;

const SUPPORTED_POLICIES = [
  {
    key: "NewTabPageLocation",
    type: "string",
    default: "https://outlook.com",
    placeholder: "https://outlook.com",
  },
  {
    key: "ShowHomeButton",
    type: "bool",
    default: false,
  },
  {
    key: "DownloadRestrictions",
    type: "int",
    default: 3,
    placeholder: "3",
  },
  {
    key: "DownloadDirectory",
    type: "string",
    default: "/Users/Shared/edc",
    placeholder: "/Users/Shared/edc",
  },
  {
    key: "PrintingEnabled",
    type: "bool",
    default: false,
  },
  {
    key: "DeveloperToolsAvailability",
    type: "int",
    default: 2,
    placeholder: "2",
  },
  {
    key: "ScreenCaptureAllowed",
    type: "bool",
    default: false,
  },
  {
    key: "DefaultClipboardSetting",
    type: "int",
    default: 2,
    placeholder: "2",
  },
  {
    key: "ClipboardAllowedForUrls",
    type: "list",
    default: ["https://accops.com", "https://*.accops.com"],
    placeholder: "One URL per line",
  },
];

function openBrowser(url) {
  let command;
  if (process.platform === "darwin") {
    command = `open "${url}"`;
  } else if (process.platform === "win32") {
    command = `start "" "${url}"`;
  } else {
    command = `xdg-open "${url}"`;
  }

  exec(command, (error) => {
    if (error) {
      console.log(`Open browser manually at ${url}`);
    }
  });
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Policy JSON Builder</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --line: #dbe4ea;
      --text: #10212b;
      --muted: #52606d;
      --accent: #0f766e;
      --accent-dark: #115e59;
      --soft: #edf7f5;
      --code: #0f172a;
      --code-text: #dbeafe;
      --warn: #b45309;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, #d1fae5 0, transparent 30%),
        radial-gradient(circle at bottom right, #dbeafe 0, transparent 35%),
        var(--bg);
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      overflow: hidden;
    }
    .wrap {
      width: 100%;
      max-width: none;
      margin: 0;
      padding: 18px 20px;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .hero {
      margin-bottom: 20px;
      flex: 0 0 auto;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 30px;
    }
    .subtitle {
      margin: 0;
      color: var(--muted);
      max-width: 860px;
    }
    .grid {
      display: grid;
      grid-template-columns: 7fr 3fr;
      gap: 20px;
      align-items: stretch;
      flex: 1 1 auto;
      min-height: 0;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 14px 40px rgba(15, 23, 42, 0.06);
    }
    .card h2 {
      margin: 0 0 14px;
      font-size: 18px;
    }
    .toolbar {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    button {
      border: 0;
      border-radius: 10px;
      padding: 10px 14px;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      background: var(--accent);
      color: #fff;
      transition: background 0.2s ease;
    }
    button:hover {
      background: var(--accent-dark);
    }
    button.secondary {
      background: #e5e7eb;
      color: var(--text);
    }
    button.secondary:hover {
      background: #d1d5db;
    }
    .policy-row {
      display: grid;
      grid-template-columns: 28px 220px 1fr 88px;
      gap: 12px;
      align-items: start;
      padding: 12px 0;
      border-top: 1px solid #edf2f7;
      transition: background 0.18s ease, transform 0.18s ease;
    }
    .policy-row:first-of-type {
      border-top: 0;
    }
    .policy-row:hover {
      background: #f8fafc;
      transform: translateY(-1px);
    }
    .policy-key {
      font-weight: 700;
    }
    .policy-type {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    input[type="text"], input[type="number"], textarea, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px 12px;
      font: inherit;
      color: var(--text);
      background: #fff;
    }
    input[type="text"]:focus,
    input[type="number"]:focus,
    textarea:focus,
    select:focus,
    button:focus,
    input[type="checkbox"]:focus {
      outline: 3px solid rgba(15, 118, 110, 0.18);
      outline-offset: 2px;
    }
    textarea {
      min-height: 90px;
      resize: vertical;
    }
    .bool-wrap {
      display: flex;
      align-items: center;
      min-height: 42px;
    }
    .custom-grid {
      display: grid;
      grid-template-columns: 1fr 140px;
      gap: 10px;
      margin-bottom: 10px;
    }
    .custom-grid .full {
      grid-column: 1 / -1;
    }
    .hint, .storage-note {
      margin: 10px 0 0;
      color: var(--muted);
      font-size: 12px;
    }
    .storage-note {
      color: var(--warn);
      margin-bottom: 14px;
    }
    pre {
      margin: 0;
      padding: 14px;
      border-radius: 12px;
      background: var(--code);
      color: var(--code-text);
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .section {
      display: flex;
      flex-direction: column;
      gap: 12px;
      min-height: 0;
      overflow: hidden;
    }
    .right-top-card {
      flex: 0 0 auto;
    }
    .output-stack {
      display: grid;
      grid-template-rows: minmax(0, 1fr) minmax(0, 1fr);
      gap: 12px;
      min-height: 0;
      flex: 1 1 auto;
    }
    .policy-card {
      display: flex;
      flex-direction: column;
      min-height: 0;
      height: 100%;
      overflow: hidden;
    }
    .policy-list-scroll {
      min-height: 0;
      overflow: auto;
      padding-right: 4px;
    }
    .policy-list-scroll::-webkit-scrollbar {
      width: 10px;
    }
    .policy-list-scroll::-webkit-scrollbar-thumb {
      background: #cbd5e1;
      border-radius: 999px;
      border: 2px solid transparent;
      background-clip: padding-box;
    }
    .policy-list-scroll::-webkit-scrollbar-track {
      background: transparent;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 9px;
      border-radius: 999px;
      background: #ecfeff;
      color: #155e75;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-top: 6px;
    }
    .delete-btn {
      background: #fff1f2;
      color: #be123c;
      border: 1px solid #fecdd3;
      padding: 8px 10px;
      width: 100%;
    }
    .delete-btn:hover {
      background: #ffe4e6;
    }
    .delete-slot {
      display: flex;
      align-items: center;
      min-height: 42px;
    }
    .output-card {
      display: flex;
      flex-direction: column;
      min-height: 0;
    }
    .output-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 10px;
    }
    .output-header h2 {
      margin: 0;
      font-size: 17px;
    }
    .copy-btn {
      background: #ecfeff;
      color: #155e75;
      border: 1px solid #bae6fd;
      padding: 8px 11px;
      white-space: nowrap;
    }
    .copy-btn:hover {
      background: #cffafe;
    }
    .compact-pre {
      flex: 1 1 auto;
      min-height: 0;
      max-height: none;
      border: 1px solid #1e293b;
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
    }
    .hint {
      margin-top: 8px;
    }
    @media (max-width: 980px) {
      body {
        overflow: auto;
      }
      .wrap {
        height: auto;
        min-height: 100vh;
        padding: 14px;
      }
      .grid {
        grid-template-columns: 1fr;
      }
      .section {
        overflow: visible;
      }
      .output-stack {
        grid-template-rows: auto;
      }
      .policy-row {
        grid-template-columns: 28px 1fr;
      }
      .policy-row > div:nth-child(3),
      .policy-row > div:nth-child(4) {
        grid-column: 1 / -1;
      }
      .custom-grid {
        grid-template-columns: 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Policy JSON Builder</h1>
      <p class="subtitle">Build supported Chromium policies plus your own custom policies. The page stores policy definitions and current selections in browser storage, and outputs plain JSON plus Base64 only.</p>
    </div>

    <div class="grid">
      <section class="card policy-card">
        <h2>Policies</h2>
        <div class="toolbar">
          <button type="button" onclick="applyDefaults()">Use Defaults</button>
          <button type="button" class="secondary" onclick="clearSelection()">Clear All</button>
          <button type="button" class="secondary" onclick="resetCustomPolicies()">Reset Custom Policies</button>
        </div>
        <div id="policyList" class="policy-list-scroll"></div>
      </section>

      <section class="section">
        <div class="card right-top-card" style="background: linear-gradient(180deg, #f0fdfa 0%, #ffffff 100%);">
          <h2>Add Custom Policy</h2>
          <div class="custom-grid">
            <input id="customKey" type="text" placeholder="Policy key">
            <select id="customType" onchange="updateCustomValueField()">
              <option value="string">string</option>
              <option value="int">int</option>
              <option value="bool">bool</option>
              <option value="list">list&lt;string&gt;</option>
            </select>
            <div id="customValueHolder" class="full"></div>
          </div>
          <button type="button" onclick="addCustomPolicy()">Add Custom Policy</button>
          <p class="storage-note">Custom policies and current selections are stored in browser localStorage.</p>
        </div>

        <div class="output-stack">
          <div class="card output-card">
            <div class="output-header">
              <h2>Policy JSON</h2>
              <button type="button" class="copy-btn" onclick="copyOutput('jsonOutput', this)">Copy JSON</button>
            </div>
            <pre id="jsonOutput" class="compact-pre">{}</pre>
            <p class="hint">Exact JSON object generated from enabled policies.</p>
          </div>
          <div class="card output-card">
            <div class="output-header">
              <h2>Base64</h2>
              <button type="button" class="copy-btn" onclick="copyOutput('base64Output', this)">Copy Base64</button>
            </div>
            <pre id="base64Output" class="compact-pre">e30=</pre>
            <p class="hint">Base64 of the compact JSON object above.</p>
          </div>
        </div>
      </section>
    </div>
  </div>

  <script>
    const BASE_POLICIES = ${JSON.stringify(SUPPORTED_POLICIES)};
    const STORAGE_KEYS = {
      customPolicies: "hyconnect_custom_policies_v2",
      selections: "hyconnect_policy_selections_v2",
    };

    let policies = [];
    let customPolicies = [];

    function cloneValue(value) {
      return Array.isArray(value) ? [...value] : value;
    }

    function toggleId(key) {
      return "toggle_" + key;
    }

    function inputId(key) {
      return "input_" + key;
    }

    function getDefaultEnabled(policy) {
      return policy.default !== "" &&
             !(Array.isArray(policy.default) && policy.default.length === 0);
    }

    function saveSelections() {
      const selections = {};
      policies.forEach((policy) => {
        const toggle = document.getElementById(toggleId(policy.key));
        const input = document.getElementById(inputId(policy.key));
        if (!toggle || !input) {
          return;
        }
        let value;
        if (policy.type === "bool") {
          value = input.checked;
        } else if (policy.type === "list") {
          value = input.value;
        } else {
          value = input.value;
        }
        selections[policy.key] = {
          enabled: toggle.checked,
          value,
        };
      });
      localStorage.setItem(STORAGE_KEYS.selections, JSON.stringify(selections));
    }

    function loadSelections() {
      try {
        return JSON.parse(localStorage.getItem(STORAGE_KEYS.selections) || "{}");
      } catch {
        return {};
      }
    }

    function saveCustomPolicies() {
      localStorage.setItem(STORAGE_KEYS.customPolicies, JSON.stringify(customPolicies));
    }

    function loadCustomPolicies() {
      try {
        customPolicies = JSON.parse(localStorage.getItem(STORAGE_KEYS.customPolicies) || "[]");
      } catch {
        customPolicies = [];
      }
      policies = [...BASE_POLICIES, ...customPolicies];
    }

    function updateCustomValueField() {
      const type = document.getElementById("customType").value;
      const holder = document.getElementById("customValueHolder");
      if (type === "bool") {
        holder.innerHTML = '<label class="bool-wrap"><input id="customValueBool" type="checkbox"> Default true</label>';
      } else if (type === "list") {
        holder.innerHTML = '<textarea id="customValueList" placeholder="One string per line"></textarea>';
      } else if (type === "int") {
        holder.innerHTML = '<input id="customValueText" type="number" placeholder="Default integer value">';
      } else {
        holder.innerHTML = '<input id="customValueText" type="text" placeholder="Default string value">';
      }
    }

    function getCustomDefaultValue() {
      const type = document.getElementById("customType").value;
      if (type === "bool") {
        return document.getElementById("customValueBool").checked;
      }
      if (type === "list") {
        return document.getElementById("customValueList").value
          .split("\\n")
          .map((item) => item.trim())
          .filter(Boolean);
      }
      if (type === "int") {
        const raw = document.getElementById("customValueText").value.trim();
        return raw === "" ? 0 : Number.parseInt(raw, 10);
      }
      return document.getElementById("customValueText").value.trim();
    }

    function addCustomPolicy() {
      const key = document.getElementById("customKey").value.trim();
      const type = document.getElementById("customType").value;
      if (!key) {
        alert("Policy key is required.");
        return;
      }
      if (policies.some((policy) => policy.key.toLowerCase() === key.toLowerCase())) {
        alert("Policy key already exists.");
        return;
      }

      customPolicies.push({
        key,
        type,
        default: getCustomDefaultValue(),
        placeholder: type === "list" ? "One string per line" : "",
      });
      saveCustomPolicies();
      loadCustomPolicies();
      renderPolicies();

      document.getElementById("customKey").value = "";
      document.getElementById("customType").value = "string";
      updateCustomValueField();
    }

    function isCustomPolicy(key) {
      return customPolicies.some((policy) => policy.key === key);
    }

    function deleteCustomPolicy(key) {
      customPolicies = customPolicies.filter((policy) => policy.key !== key);
      saveCustomPolicies();

      const selections = loadSelections();
      delete selections[key];
      localStorage.setItem(STORAGE_KEYS.selections, JSON.stringify(selections));

      loadCustomPolicies();
      renderPolicies();
    }

    function resetCustomPolicies() {
      customPolicies = [];
      saveCustomPolicies();
      localStorage.removeItem(STORAGE_KEYS.selections);
      loadCustomPolicies();
      renderPolicies();
    }

    function renderInput(policy, savedSelection) {
      const savedValue = savedSelection ? savedSelection.value : undefined;
      if (policy.type === "bool") {
        const checked = typeof savedValue === "boolean" ? savedValue : Boolean(policy.default);
        return '<div class="bool-wrap"><label><input type="checkbox" id="' + inputId(policy.key) + '"' +
          (checked ? " checked" : "") + '> Value</label></div>';
      }
      if (policy.type === "list") {
        const text = Array.isArray(savedValue) ? savedValue.join("\\n") :
          typeof savedValue === "string" ? savedValue :
          (policy.default || []).join("\\n");
        return '<textarea id="' + inputId(policy.key) + '" placeholder="' + (policy.placeholder || "") + '">' + text + '</textarea>';
      }
      const value = savedSelection ? savedValue : policy.default;
      const inputType = policy.type === "int" ? "number" : "text";
      return '<input id="' + inputId(policy.key) + '" type="' + inputType + '" value="' + String(value ?? "").replaceAll('"', "&quot;") + '" placeholder="' + (policy.placeholder || "") + '">';
    }

    function renderPolicies() {
      const savedSelections = loadSelections();
      const container = document.getElementById("policyList");
      container.innerHTML = "";

      policies.forEach((policy) => {
        const row = document.createElement("div");
        row.className = "policy-row";
        const savedSelection = savedSelections[policy.key];
        const enabled = savedSelection ? savedSelection.enabled : getDefaultEnabled(policy);
        const customBadge = isCustomPolicy(policy.key)
          ? '<div class="pill">Custom</div>'
          : "";
        const deleteAction = isCustomPolicy(policy.key)
          ? '<div class="delete-slot"><button type="button" class="delete-btn" data-delete-key="' + policy.key.replaceAll('"', "&quot;") + '">Delete</button></div>'
          : '<div class="delete-slot"></div>';

        row.innerHTML = 
          '<div><input type="checkbox" id="' + toggleId(policy.key) + '"' + (enabled ? " checked" : "") + "></div>" +
          '<div><div class="policy-key">' + policy.key + '</div><div class="policy-type">' +
          (policy.type === "list" ? "list<string>" : policy.type) + '</div>' + customBadge + '</div>' +
          '<div>' + renderInput(policy, savedSelection) + '</div>' +
          deleteAction;
        container.appendChild(row);
      });

      policies.forEach((policy) => {
        document.getElementById(toggleId(policy.key)).addEventListener("change", updateOutputs);
        document.getElementById(inputId(policy.key)).addEventListener("input", updateOutputs);
        document.getElementById(inputId(policy.key)).addEventListener("change", updateOutputs);
      });

      container.querySelectorAll("[data-delete-key]").forEach((button) => {
        button.addEventListener("click", () => deleteCustomPolicy(button.dataset.deleteKey));
      });

      updateOutputs();
    }

    function getPolicyValue(policy) {
      const input = document.getElementById(inputId(policy.key));
      if (policy.type === "bool") {
        return input.checked;
      }
      if (policy.type === "int") {
        const raw = input.value.trim();
        return raw === "" ? null : Number.parseInt(raw, 10);
      }
      if (policy.type === "list") {
        return input.value
          .split("\\n")
          .map((item) => item.trim())
          .filter(Boolean);
      }
      return input.value.trim();
    }

    function buildPolicyJson() {
      const output = {};
      policies.forEach((policy) => {
        const enabled = document.getElementById(toggleId(policy.key)).checked;
        if (!enabled) {
          return;
        }
        const value = getPolicyValue(policy);
        if (value === null) {
          return;
        }
        output[policy.key] = value;
      });
      return output;
    }

    function updateOutputs() {
      const policyJson = buildPolicyJson();
      const compact = JSON.stringify(policyJson);
      document.getElementById("jsonOutput").textContent = JSON.stringify(policyJson, null, 2);
      document.getElementById("base64Output").textContent =
        btoa(unescape(encodeURIComponent(compact)));
      saveSelections();
    }

    async function copyOutput(elementId, button) {
      const text = document.getElementById(elementId).textContent;
      try {
        await navigator.clipboard.writeText(text);
        const original = button.textContent;
        button.textContent = "Copied";
        setTimeout(() => {
          button.textContent = original;
        }, 1200);
      } catch {
        alert("Copy failed.");
      }
    }

    function applyDefaults() {
      localStorage.removeItem(STORAGE_KEYS.selections);
      renderPolicies();
    }

    function clearSelection() {
      policies.forEach((policy) => {
        const toggle = document.getElementById(toggleId(policy.key));
        if (toggle) {
          toggle.checked = false;
        }
      });
      updateOutputs();
    }

    loadCustomPolicies();
    updateCustomValueField();
    renderPolicies();
  </script>
</body>
</html>`;

const server = http.createServer((req, res) => {
  if (req.url !== "/") {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found");
    return;
  }

  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`Policy JSON Builder running at ${APP_URL}`);
  openBrowser(APP_URL);
});
