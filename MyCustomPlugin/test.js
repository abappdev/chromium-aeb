#!/usr/bin/env node

/**
 * HyConnect Policy Dashboard Server (ESM)
 * - Interactive policy selection table with Tailwind CSS
 * - Real-time JSON/Base64/AES-256-GCM outputs
 * - Toggle Login / Logout
 */

import http from "node:http";
import { exec } from "node:child_process";
import crypto from "node:crypto";

const PORT = 16271;
const ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
const ALGO_AES_256_GCM = 0x01;

let loggedIn = false;
let clients = [];

const POLICIES = [
  /* --- Startup / Homepage --- */
  { key: "HomepageLocation", type: "string", default: "" },
  { key: "HomepageIsNewTabPage", type: "bool", default: false },
  { key: "RestoreOnStartup", type: "int", default: 0 },
  { key: "RestoreOnStartupURLs", type: "string", default: "" },
  /* --- Downloads --- */
  { key: "DownloadRestrictions", type: "int", default: 0 },
  { key: "PromptForDownloadLocation", type: "bool", default: false },
  { key: "DefaultDownloadDirectory", type: "string", default: "" },
  { key: "AllowFileSelectionDialogs", type: "bool", default: true },
  /* --- Incognito / Privacy --- */
  { key: "IncognitoModeAvailability", type: "int", default: 0 },
  { key: "SavingBrowserHistoryDisabled", type: "bool", default: false },
  { key: "ClearBrowsingDataOnExit", type: "bool", default: false },
  { key: "AllowDeletingBrowserHistory", type: "bool", default: true },
  /* --- Passwords / Autofill --- */
  { key: "PasswordManagerEnabled", type: "bool", default: true },
  { key: "AutofillEnabled", type: "bool", default: true },
  { key: "AutofillAddressEnabled", type: "bool", default: true },
  { key: "AutofillCreditCardEnabled", type: "bool", default: true },
  /* --- Security / Safe Browsing --- */
  { key: "SafeBrowsingEnabled", type: "bool", default: true },
  { key: "SafeBrowsingProtectionLevel", type: "int", default: 1 },
  { key: "DisableSafeBrowsingProceedAnyway", type: "bool", default: false },
  { key: "SSLErrorOverrideAllowed", type: "bool", default: true },
  /* --- Extensions --- */
  { key: "ExtensionInstallBlocklist", type: "string", default: "" },
  { key: "ExtensionInstallAllowlist", type: "string", default: "" },
  { key: "ExtensionInstallForcelist", type: "string", default: "" },
  { key: "ExtensionAllowedTypes", type: "string", default: "" },
  { key: "DeveloperToolsDisabled", type: "bool", default: false },
  /* --- Printing --- */
  { key: "PrintingEnabled", type: "bool", default: true },
  { key: "PrintPreviewDisabled", type: "bool", default: false },
  { key: "DisablePrintPreview", type: "bool", default: false },
  /* --- Network / Proxy --- */
  { key: "ProxyMode", type: "string", default: "" },
  { key: "ProxyServer", type: "string", default: "" },
  { key: "ProxyBypassList", type: "string", default: "" },
  { key: "EnableOnlineRevocationChecks", type: "bool", default: false },
  /* --- Cookies / Content --- */
  { key: "DefaultCookiesSetting", type: "int", default: 0 },
  { key: "BlockThirdPartyCookies", type: "bool", default: false },
  { key: "CookiesAllowedForUrls", type: "string", default: "" },
  { key: "CookiesBlockedForUrls", type: "string", default: "" },
  /* --- Media / Clipboard --- */
  { key: "AudioCaptureAllowed", type: "bool", default: true },
  { key: "VideoCaptureAllowed", type: "bool", default: true },
  { key: "ClipboardAllowed", type: "bool", default: true },
  { key: "ClipboardAllowedForUrls", type: "string", default: "" },
  /* --- Popups / JavaScript --- */
  { key: "DefaultPopupsSetting", type: "int", default: 0 },
  { key: "JavascriptEnabled", type: "bool", default: true },
  { key: "PopupsAllowedForUrls", type: "string", default: "" },
  { key: "PopupsBlockedForUrls", type: "string", default: "" },
  /* --- Certificates / TLS --- */
  { key: "AuthSchemes", type: "string", default: "" },
  { key: "DisableAuthNegotiateCnameLookup", type: "bool", default: false },
  { key: "EnableAuthNegotiatePort", type: "bool", default: false },
  /* --- UI / UX --- */
  { key: "ShowHomeButton", type: "bool", default: true },
  { key: "BookmarkBarEnabled", type: "bool", default: true },
  { key: "EditBookmarksEnabled", type: "bool", default: true },
  { key: "BrowserAddPersonEnabled", type: "bool", default: true },
  /* --- Updates --- */
  { key: "AutoUpdateCheckPeriodMinutes", type: "int", default: 1440 },
  { key: "ComponentUpdatesEnabled", type: "bool", default: true },
  /* --- Misc --- */
  { key: "TranslateEnabled", type: "bool", default: true },
  { key: "DefaultSearchProviderEnabled", type: "bool", default: true },
  { key: "DefaultSearchProviderName", type: "string", default: "" },
  { key: "DefaultSearchProviderSearchURL", type: "string", default: "" },
  { key: "NetworkPredictionOptions", type: "int", default: 0 },
  { key: "MetricsReportingEnabled", type: "bool", default: false },
  { key: "CloudReportingEnabled", type: "bool", default: false },
  { key: "SigninAllowed", type: "bool", default: true },
  { key: "SyncDisabled", type: "bool", default: false },
  { key: "BackgroundModeEnabled", type: "bool", default: true },
  { key: "HideWebStoreIcon", type: "bool", default: false },
  { key: "ForceEphemeralProfiles", type: "bool", default: false },
  { key: "BrowserSignin", type: "int", default: 0 },
  { key: "NewTabPageLocation", type: "string", default: "" },
  { key: "TaskManagerEndProcessEnabled", type: "bool", default: true },
  { key: "AllowCrossOriginAuthPrompt", type: "bool", default: false },
  { key: "EnableMediaRouter", type: "bool", default: true },
  { key: "MediaRouterCastAllowAllIPs", type: "bool", default: false },
  { key: "EnableDeprecatedWebPlatformFeatures", type: "bool", default: false },
];

// Store selected policies and encrypted data
let selectedPolicies = {};
let streamFormat = "encrypted"; // 'encrypted' or 'base64'

const policiesJSON = JSON.stringify(POLICIES);

function encryptData(base64Data) {
  const algorithm = "aes-256-gcm";
  const key = Buffer.from(ENCRYPTION_KEY, "utf8");
  const ivLength = 12;

  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(base64Data, "utf8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  const authTag = cipher.getAuthTag();

  const algoIdBuf = Buffer.from([ALGO_AES_256_GCM]);
  const combined = Buffer.concat([algoIdBuf, iv, encrypted, authTag]);

  return combined.toString("base64");
}

function getDecodedPolicy() {
  return loggedIn ? selectedPolicies : {};
}

function getPolicyPayload() {
  const policy = getDecodedPolicy();
  const jsonStr = JSON.stringify(policy);
  const base64 = Buffer.from(jsonStr).toString("base64");

  // Log for debugging
  console.log("=== POLICY PAYLOAD DEBUG ===");
  console.log("Login Status:", loggedIn);
  console.log("Stream Format:", streamFormat);
  console.log("Original JSON:", jsonStr);
  console.log("Base64 Encoded:", base64);
  // Calculate payload based on format
  let finalPayload = base64;
  if (streamFormat === "encrypted") {
    finalPayload = encryptData(base64);
    console.log("Sending Encrypted Data (len):", finalPayload.length);
  }
  console.log("=======================");

  return {
    loginStatus: loggedIn,
    policydata: finalPayload,
  };
}

function sendPolicy() {
  const payload = getPolicyPayload();
  const data = `data: ${JSON.stringify(payload)}\n\n`;

  clients.forEach((res) => res.write(data));
  console.log("Policy sent to", clients.length, "client(s)");
}

/* ------------------ HTTP Server ------------------ */

const server = http.createServer((req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  // Serve dashboard HTML
  if (req.url === "/") {
    const policiesJSON = JSON.stringify(POLICIES);
    const decoded = JSON.stringify(getDecodedPolicy(), null, 2);
    const base64 = Buffer.from(JSON.stringify(getDecodedPolicy())).toString(
      "base64",
    );
    const encrypted = getPolicyPayload().policydata;

    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HyConnect Policy Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    * { font-family: 'Inter', sans-serif; }
    
    /* Custom scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #f4f4f5; }
    ::-webkit-scrollbar-thumb { background: #a1a1aa; border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #71717a; }
    
    /* Text utilities */
    .wrap-text { white-space: pre-wrap; word-wrap: break-word; overflow-wrap: break-word; }
    
    /* Table layout */
    table { table-layout: fixed; width: 100%; }
    td, th { word-wrap: break-word; overflow-wrap: break-word; }
    td { max-width: 0; }
    
    /* Encoded output formatting */
    #base64Output, #encryptedOutput {
      word-break: break-all;
      white-space: pre-wrap;
    }
    
    /* Modern card design */
    .policy-row {
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .policy-row:hover {
      background: linear-gradient(to right, #f9fafb, #f3f4f6);
      transform: translateY(-1px);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
    }
    
    /* Collapsible cards */
    .output-card { 
      overflow: hidden;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .output-card.collapsed .output-content { 
      max-height: 0; 
      opacity: 0; 
      margin: 0; 
      padding: 0; 
      overflow: hidden; 
      transition: all 0.3s ease;
    }
    .output-card:not(.collapsed) .output-content { 
      max-height: 500px; 
      opacity: 1; 
      transition: all 0.3s ease;
    }
    .output-card.collapsed .expand-icon { transform: rotate(-90deg); }
    .output-card:hover { 
      border-color: #e4e4e7;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
    
    /* Glass morphism */
    .glass {
      background: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }
    
    /* Button enhancements */
    button {
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    /* Input focus states */
    input:focus, select:focus {
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    
    /* Badge styles */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
      padding: 0.25rem 0.75rem;
      font-size: 0.75rem;
      font-weight: 600;
      border-radius: 9999px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
  </style>
</head>
<body class="bg-zinc-50 min-h-screen">
  <header class="bg-white border-b border-zinc-200 sticky top-0 z-50 shadow-sm">
    <div class="px-6 py-4 flex justify-between items-center gap-6">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 bg-gradient-to-br from-blue-600 to-indigo-600 rounded-lg flex items-center justify-center shadow-sm">
          <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
          </svg>
        </div>
        <div>
          <h1 class="text-lg font-semibold text-zinc-900">HyConnect Policy Dashboard</h1>
          <p class="text-xs text-zinc-500">Enterprise Policy Management</p>
        </div>
      </div>
      <div class="flex-1 flex justify-center max-w-2xl">
        <input type="text" id="policySearch" placeholder="🔍 Search policies..." class="px-4 py-2 border border-zinc-200 bg-white text-zinc-900 placeholder-zinc-400 rounded-lg text-sm focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 w-full max-w-md transition-all"/>
      </div>
      <div class="flex items-center gap-3">
        <span class="badge ${loggedIn ? "bg-emerald-100 text-emerald-700 border border-emerald-200" : "bg-rose-100 text-rose-700 border border-rose-200"}">${loggedIn ? "✓ Logged In" : "✗ Logged Out"}</span>
        <button onclick="toggle()" class="px-4 py-2 ${loggedIn ? "bg-rose-600 hover:bg-rose-700" : "bg-emerald-600 hover:bg-emerald-700"} text-white rounded-lg font-medium text-sm shadow-sm hover:shadow transition-all">${loggedIn ? "Logout" : "Login"}</button>
      </div>
    </div>
  </header>

  <div class="flex h-[calc(100vh-73px)]">
    <div class="w-[60%] flex flex-col bg-white border-r border-zinc-200">
      <div class="flex-1 overflow-y-auto">
        <table class="w-full text-sm">
          <thead class="sticky top-0 z-10 bg-zinc-100 border-b border-zinc-200">
            <tr>
              <th class="px-4 py-3 text-left font-medium text-xs text-zinc-700 uppercase tracking-wider w-12">Sr</th>
              <th class="px-4 py-3 text-left font-medium text-xs text-zinc-700 uppercase tracking-wider w-40">Policy Name</th>
              <th class="px-4 py-3 text-left font-medium text-xs text-zinc-700 uppercase tracking-wider w-20">Type</th>
              <th class="px-4 py-3 text-left font-medium text-xs text-zinc-700 uppercase tracking-wider w-40">Value</th>
              <th class="px-4 py-3 text-center font-medium text-xs text-zinc-700 uppercase tracking-wider w-16">Enable</th>
              <th class="px-4 py-3 text-center font-medium text-xs text-zinc-700 uppercase tracking-wider w-16">Action</th>
            </tr>
          </thead>
          <tbody id="policyTableBody" class="bg-white divide-y divide-zinc-100"></tbody>
        </table>
      </div>
    </div>

    <div class="w-[40%] flex flex-col bg-zinc-50">
      <div class="px-6 py-4 bg-white border-b border-zinc-200 flex justify-between items-center">
        <h2 class="text-lg font-semibold text-zinc-900 flex items-center gap-2">
          <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
          </svg>
          Output & Encryption
        </h2>
        <div class="flex items-center gap-2">
          <span class="text-xs text-zinc-600 font-medium">Stream Format:</span>
          <button onclick="toggleStreamFormat()" id="streamFormatBtn" class="px-3 py-1.5 border border-zinc-300 rounded-lg text-xs font-medium hover:bg-zinc-50 transition-all ${streamFormat === "base64" ? "bg-blue-100 text-blue-700" : ""}">
            ${streamFormat === "encrypted" ? "Encrypted" : "Base64"}
          </button>
        </div>
      </div>
      <div class="flex-1 overflow-y-auto p-6 space-y-5">
        <!-- Custom Policy Addition Card -->
        <div class="bg-white rounded-lg p-5 shadow-sm border border-zinc-200">
          <div class="flex items-center gap-2 mb-4">
            <div class="w-8 h-8 bg-emerald-100 text-emerald-600 rounded-lg flex items-center justify-center font-bold">
              +
            </div>
            <h3 class="text-sm font-semibold text-zinc-900">Add Custom Policy</h3>
          </div>
          <div class="space-y-3">
            <input type="text" id="customPolicyName" placeholder="Policy name" class="w-full px-3 py-2 border border-zinc-200 rounded-lg text-sm focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100 bg-white transition-all"/>
            <div class="flex gap-2">
              <select id="customPolicyType" onchange="updateValueInputType()" class="flex-1 px-3 py-2 border border-zinc-200 rounded-lg text-sm focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100 bg-white transition-all">
                <option value="string">string</option>
                <option value="int">int</option>
                <option value="bool">bool</option>
              </select>
              <div id="customPolicyValueContainer" class="flex-[2]">
                <input type="text" id="customPolicyValue" placeholder="Value (optional)" class="w-full px-3 py-2 border border-zinc-200 rounded-lg text-sm focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100 bg-white transition-all"/>
              </div>
            </div>
            <button onclick="handleAddCustomPolicy()" class="w-full px-4 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg font-medium text-sm shadow-sm hover:shadow transition-all">
              + Add Custom Policy
            </button>
          </div>
        </div>

        <div class="output-card bg-white rounded-lg p-4 shadow-sm border border-zinc-200 transition-all duration-300">
          <div class="flex items-center gap-2 mb-3 cursor-pointer" onclick="toggleCard(this)">
            <div class="w-7 h-7 bg-blue-100 text-blue-600 rounded-lg flex items-center justify-center text-xs font-semibold">1</div>
            <h3 class="text-sm font-medium text-zinc-900">Decoded Policy JSON</h3>
            <svg class="expand-icon w-4 h-4 ml-auto text-zinc-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </div>
          <pre id="jsonOutput" class="output-content bg-zinc-900 text-emerald-400 p-3 rounded-md text-xs leading-relaxed font-mono wrap-text max-h-64 overflow-auto">${decoded}</pre>
        </div>

        <div class="output-card bg-white rounded-lg p-4 shadow-sm border border-zinc-200 transition-all duration-300">
          <div class="flex items-center gap-2 mb-3 cursor-pointer" onclick="toggleCard(this)">
            <div class="w-7 h-7 bg-amber-100 text-amber-600 rounded-lg flex items-center justify-center text-xs font-semibold">2</div>
            <h3 class="text-sm font-medium text-zinc-900">Base64 Encoded</h3>
            <svg class="expand-icon w-4 h-4 ml-auto text-zinc-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </div>
          <pre id="base64Output" class="output-content bg-zinc-900 text-amber-400 p-3 rounded-md text-xs leading-relaxed font-mono wrap-text max-h-48 overflow-auto">${base64}</pre>
        </div>

        <div class="output-card bg-white rounded-lg p-4 shadow-sm border border-zinc-200 transition-all duration-300">
          <div class="flex items-center gap-2 mb-3 cursor-pointer" onclick="toggleCard(this)">
            <div class="w-7 h-7 bg-purple-100 text-purple-600 rounded-lg flex items-center justify-center text-xs font-semibold">3</div>
            <h3 class="text-sm font-medium text-zinc-900">AES-256-GCM Encrypted</h3>
            <svg class="expand-icon w-4 h-4 ml-auto text-zinc-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </div>
          <pre id="encryptedOutput" class="output-content bg-zinc-900 text-purple-400 p-3 rounded-md text-xs leading-relaxed font-mono wrap-text max-h-48 overflow-auto">${encrypted}</pre>
          <p class="output-content text-xs text-zinc-500 mt-2">Format: [AlgoID(1)] + [IV(12)] + [Ciphertext] + [AuthTag(16)]</p>
        </div>

        <div class="output-card bg-white rounded-lg p-4 shadow-sm border border-zinc-200 transition-all duration-300">
          <div class="flex items-center gap-2 mb-3 cursor-pointer" onclick="toggleCard(this)">
            <div class="w-7 h-7 bg-indigo-100 text-indigo-600 rounded-lg flex items-center justify-center text-xs font-semibold">4</div>
            <h3 class="text-sm font-medium text-zinc-900">SSE Response Stream</h3>
            <svg class="expand-icon w-4 h-4 ml-auto text-zinc-400 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </div>
          <pre id="sseResponse" class="output-content bg-zinc-900 text-cyan-400 p-3 rounded-md text-xs leading-relaxed font-mono wrap-text max-h-48 overflow-auto">{"loginStatus": true, "policydata": "..."}</pre>
          <p class="output-content text-xs text-zinc-500 mt-2">Actual payload sent to browser via SSE</p>
        </div>
      </div>
    </div>
  </div>

  <script>
    const BASE_POLICIES = ${policiesJSON};
    let customPolicies = [];
    let loggedIn = ${loggedIn};
    let POLICIES = [];
    let selectedPolicies = {};
    let filteredPolicies = [];
    let streamFormat = '${streamFormat}'; // 'encrypted' or 'base64'

    // Toggle stream format
    function toggleStreamFormat() {
      streamFormat = streamFormat === 'encrypted' ? 'base64' : 'encrypted';
      const btn = document.getElementById('streamFormatBtn');
      btn.textContent = streamFormat === 'encrypted' ? 'Encrypted' : 'Base64';
      btn.classList.toggle('bg-blue-100');
      btn.classList.toggle('text-blue-700');
      
      // Sync with server
      fetch('/toggleStreamFormat')
        .then(r => r.json())
        .then(data => {
          console.log('Server stream format:', data.format);
        })
        .catch(err => console.error('Failed to toggle stream format:', err));
      
      updateOutputs();
    }

    // Toggle card expand/collapse
    function toggleCard(headerElement) {
      const card = headerElement.closest('.output-card');
      card.classList.toggle('collapsed');
    }

    // Load custom policies from localStorage
    function loadCustomPolicies() {
      try {
        const saved = localStorage.getItem('hyconnect_custom_policies');
        if (saved) {
          customPolicies = JSON.parse(saved);
          console.log('Loaded custom policies from localStorage:', customPolicies);
        }
      } catch (err) {
        console.error('Failed to load custom policies:', err);
      }
      // Merge base and custom policies
      POLICIES = [...BASE_POLICIES, ...customPolicies];
      filteredPolicies = POLICIES;
    }

    // Save custom policies to localStorage
    function saveCustomPolicies() {
      try {
        localStorage.setItem('hyconnect_custom_policies', JSON.stringify(customPolicies));
        console.log('Saved custom policies to localStorage');
      } catch (err) {
        console.error('Failed to save custom policies:', err);
      }
    }

    // Check if policy exists (case-insensitive)
    function policyExists(key) {
      const lowerKey = key.toLowerCase();
      return POLICIES.some(p => p.key.toLowerCase() === lowerKey);
    }

    // Add custom policy with validation
    function addCustomPolicy(key, type, value) {
      key = key.trim();
      type = type.toLowerCase();

      // Validate input
      if (!key) {
        alert('Policy name cannot be empty');
        return false;
      }

      if (!['string', 'int', 'bool'].includes(type)) {
        alert('Type must be string, int, or bool');
        return false;
      }

      // Check for duplicates (case-insensitive)
      if (policyExists(key)) {
        alert(\`Policy "\${key}" already exists (case-insensitive check)\`);
        return false;
      }

      // Get default value based on type
      let defaultValue;
      if (value !== undefined && value !== '') {
        // Use provided value with type conversion
        if (type === 'bool') defaultValue = (value === 'true' || value === true);
        else if (type === 'int') defaultValue = parseInt(value, 10) || 0;
        else defaultValue = value;
      } else {
        // Use type-based defaults
        if (type === 'bool') defaultValue = false;
        else if (type === 'int') defaultValue = 0;
        else defaultValue = '';
      }

      const newPolicy = { key, type, default: defaultValue, custom: true };
      customPolicies.push(newPolicy);
      POLICIES.push(newPolicy);
      filteredPolicies = POLICIES;
      
      saveCustomPolicies();
      console.log('Added custom policy:', newPolicy);
      return true;
    }

    // Delete custom policy
    function deleteCustomPolicy(key) {
      const index = customPolicies.findIndex(p => p.key === key);
      if (index !== -1) {
        customPolicies.splice(index, 1);
        POLICIES = [...BASE_POLICIES, ...customPolicies];
        filteredPolicies = POLICIES;
        delete selectedPolicies[key];
        saveCustomPolicies();
        savePolicies();
        return true;
      }
      return false;
    }

    // Load saved policies from localStorage
    function loadSavedPolicies() {
      try {
        const saved = localStorage.getItem('hyconnect_selected_policies');
        if (saved) {
          selectedPolicies = JSON.parse(saved);
          console.log('Loaded saved policies from localStorage:', selectedPolicies);
        }
      } catch (err) {
        console.error('Failed to load saved policies:', err);
      }
    }

    // Save policies to localStorage
    function savePolicies() {
      try {
        localStorage.setItem('hyconnect_selected_policies', JSON.stringify(selectedPolicies));
        console.log('Saved policies to localStorage');
      } catch (err) {
        console.error('Failed to save policies:', err);
      }
    }

    function renderTable() {
      const tbody = document.getElementById('policyTableBody');
      tbody.innerHTML = '';
      
      filteredPolicies.forEach((policy, idx) => {
        const isEnabled = selectedPolicies.hasOwnProperty(policy.key);
        const row = document.createElement('tr');
        row.className = \`\${isEnabled ? 'bg-emerald-50 border-l-4 border-emerald-500' : 'hover:bg-slate-50'} transition-all duration-150\`;
        
        const currentValue = selectedPolicies[policy.key] !== undefined ? selectedPolicies[policy.key] : policy.default;
        let valueInput = '';
        
        if (policy.type === 'bool') {
          valueInput = \`<select data-key="\${policy.key}" class="policy-value w-full px-2 py-1.5 border border-slate-300 rounded-md text-xs focus:ring-2 focus:ring-blue-500 \${!isEnabled ? 'opacity-50' : ''}" \${!isEnabled ? 'disabled' : ''}><option value="true" \${currentValue === true ? 'selected' : ''}>true</option><option value="false" \${currentValue === false ? 'selected' : ''}>false</option></select>\`;
        } else if (policy.type === 'int') {
          valueInput = \`<input type="number" data-key="\${policy.key}" class="policy-value w-full px-2 py-1.5 border border-slate-300 rounded-md text-xs focus:ring-2 focus:ring-blue-500 \${!isEnabled ? 'opacity-50' : ''}" value="\${currentValue}" \${!isEnabled ? 'disabled' : ''} />\`;
        } else {
          valueInput = \`<input type="text" data-key="\${policy.key}" class="policy-value w-full px-2 py-1.5 border border-slate-300 rounded-md text-xs focus:ring-2 focus:ring-blue-500 \${!isEnabled ? 'opacity-50' : ''}" value="\${currentValue}" \${!isEnabled ? 'disabled' : ''} />\`;
        }
        
        const typeColors = { 'string': 'bg-blue-100 text-blue-700', 'int': 'bg-orange-100 text-orange-700', 'bool': 'bg-purple-100 text-purple-700' };
        
        const policyNameDisplay = policy.custom 
          ? \`\${policy.key} <span class="ml-1 px-2 py-0.5 bg-emerald-500 text-white text-xs rounded-full">CUSTOM</span>\` 
          : policy.key;

        const deleteButton = policy.custom 
          ? \`<button onclick="handleDeleteCustomPolicy('\${policy.key}')" class="px-2 py-1 bg-red-500 hover:bg-red-600 text-white rounded text-xs font-semibold">Delete</button>\`
          : '';
        
        row.innerHTML = \`
          <td class="px-3 py-2.5 text-center text-slate-500 font-semibold">\${idx + 1}</td>
          <td class="px-3 py-2.5 font-medium text-slate-700">\${policyNameDisplay}</td>
          <td class="px-3 py-2.5"><span class="inline-block px-2 py-1 rounded-md text-xs font-semibold \${typeColors[policy.type]}">\${policy.type}</span></td>
          <td class="px-3 py-2.5">\${valueInput}</td>
          <td class="px-3 py-2.5 text-center"><input type="checkbox" class="policy-select w-5 h-5 rounded border-slate-300 text-blue-600 cursor-pointer" data-key="\${policy.key}" \${isEnabled ? 'checked' : ''} /></td>
          <td class="px-3 py-2.5 text-center">\${deleteButton}</td>
        \`;
        tbody.appendChild(row);
      });
      attachEvents();
    }

    function attachEvents() {
      document.querySelectorAll('.policy-select').forEach(el => {
        el.onchange = e => {
          const key = e.target.dataset.key;
          if (e.target.checked) {
            selectedPolicies[key] = POLICIES.find(p => p.key === key).default;
          } else {
            delete selectedPolicies[key];
          }
          savePolicies();
          renderTable();
          updateOutputs();
        };
      });

      document.querySelectorAll('.policy-value').forEach(el => {
        el.onchange = e => {
          const key = e.target.dataset.key;
          const policy = POLICIES.find(p => p.key === key);
          let val = e.target.value;
          if (policy.type === 'bool') val = (val === 'true');
          if (policy.type === 'int') val = parseInt(val || '0', 10);
          selectedPolicies[key] = val;
          savePolicies();
          updateOutputs();
        };
      });

      document.getElementById('policySearch').oninput = e => {
        filteredPolicies = POLICIES.filter(p => p.key.toLowerCase().includes(e.target.value.toLowerCase()));
        renderTable();
      };
    }

    function updateOutputs() {
      const output = Object.keys(selectedPolicies).reduce((acc, key) => {
        acc[key] = selectedPolicies[key];
        return acc;
      }, {});

      const jsonStr = JSON.stringify(output, null, 2);
      document.getElementById('jsonOutput').textContent = jsonStr;
      const base64 = btoa(JSON.stringify(output));
      document.getElementById('base64Output').textContent = base64;

      console.log('Updating policy:', output);

      fetch('/updatePolicy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(output)
      })
      .then(r => {
        console.log('Response status:', r.status);
        if (!r.ok) throw new Error('Server error: ' + r.status);
        return r.json();
      })
      .then(data => {
        console.log('Encrypted data received:', data.encrypted);
        document.getElementById('encryptedOutput').textContent = data.encrypted;
        
        // Display SSE response based on format toggle
        const ssePayload = {
          loginStatus: loggedIn,
          policydata: streamFormat === 'encrypted' ? data.encrypted : base64
        };
        document.getElementById('sseResponse').textContent = JSON.stringify(ssePayload, null, 2);
      })
      .catch(err => {
        console.error('Failed to update encrypted output:', err);
        document.getElementById('encryptedOutput').textContent = 'Error: ' + err.message;
      });
    }

    function toggle() {
      fetch("/toggle").then(() => location.reload());
    }

    // Update value input based on selected type
    function updateValueInputType() {
      const typeSelect = document.getElementById('customPolicyType');
      const container = document.getElementById('customPolicyValueContainer');
      const type = typeSelect.value;

      if (type === 'bool') {
        container.innerHTML = \`<select id="customPolicyValue" class="px-3 py-1.5 border border-slate-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 w-full"><option value="false">false</option><option value="true">true</option></select>\`;
      } else if (type === 'int') {
        container.innerHTML = \`<input type="number" id="customPolicyValue" placeholder="Value (optional)" class="px-3 py-1.5 border border-slate-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 w-full"/>\`;
      } else {
        container.innerHTML = \`<input type="text" id="customPolicyValue" placeholder="Value (optional)" class="px-3 py-1.5 border border-slate-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500 w-full"/>\`;
      }
    }

    // Handler for adding custom policy
    function handleAddCustomPolicy() {
      const nameInput = document.getElementById('customPolicyName');
      const typeSelect = document.getElementById('customPolicyType');
      const valueInput = document.getElementById('customPolicyValue');
      
      const name = nameInput.value.trim();
      const type = typeSelect.value;
      const value = valueInput.value;
      
      if (addCustomPolicy(name, type, value)) {
        nameInput.value = '';
        valueInput.value = type === 'bool' ? 'false' : '';
        renderTable();
        alert(\`Custom policy "\${name}" added successfully!\`);
      }
    }

    // Handler for deleting custom policy
    function handleDeleteCustomPolicy(key) {
      if (confirm(\`Are you sure you want to delete custom policy "\${key}"?\`)) {
        if (deleteCustomPolicy(key)) {
          renderTable();
          updateOutputs();
          alert(\`Custom policy "\${key}" deleted successfully!\`);
        }
      }
    }

    // Load custom and saved policies from previous session
    loadCustomPolicies();
    loadSavedPolicies();
    renderTable();
    // Update outputs to reflect loaded policies
    if (Object.keys(selectedPolicies).length > 0) {
      updateOutputs();
    }

    // Initialize collapsible output cards (collapsed by default, click to expand)
    document.querySelectorAll('.output-card').forEach((card, index) => {
      // Keep first card (JSON) expanded, others collapsed
      if (index > 0) {
        card.classList.add('collapsed');
      }
    });
  </script>
</body>
</html>`);
    return;
  }

  // Toggle login
  if (req.url === "/toggle") {
    loggedIn = !loggedIn;
    console.log("📝 Login:", loggedIn ? "LOGGED IN" : "LOGGED OUT");
    sendPolicy();
    res.writeHead(200);
    res.end("Toggled");
    return;
  }

  // Toggle stream format
  if (req.url === "/toggleStreamFormat") {
    streamFormat = streamFormat === "encrypted" ? "base64" : "encrypted";
    console.log("🔄 Stream Format:", streamFormat.toUpperCase());
    sendPolicy(); // Re-send with new format
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ format: streamFormat }));
    return;
  }

  // Update policy from dashboard
  if (req.url === "/updatePolicy" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      try {
        const json = JSON.parse(body);
        if (json.data) {
          // Encrypt only request from client (legacy)
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ encrypted: encryptData(json.data) }));
          return;
        }

        // Update active policy
        selectedPolicies = json;

        // Calculate encrypted data for response to dashboard
        const base64 = Buffer.from(JSON.stringify(selectedPolicies)).toString(
          "base64",
        );
        const encrypted = encryptData(base64);

        console.log("📝 Policy Updated from Dashboard");
        sendPolicy();

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, encrypted: encrypted }));
      } catch (error) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: false, error: error.message }));
      }
    });
    return;
  }

  // SSE stream
  if (req.url === "/streamPluginPolicy") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });

    clients.push(res);
    const payload = getPolicyPayload();
    res.write(`data: ${JSON.stringify(payload)}\n\n`);

    req.on("close", () => {
      clients = clients.filter((c) => c !== res);
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

/* ------------------ Start & Auto Open ------------------ */

server.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n${"=".repeat(60)}`);
  console.log("🚀 HyConnect Policy Dashboard Server");
  console.log("=".repeat(60));
  console.log(`📊 Dashboard: ${url}`);
  console.log(`🔐 Encryption: AES-256-GCM`);
  console.log(`📝 Login: ${loggedIn ? "LOGGED IN" : "LOGGED OUT"}`);
  console.log(`${"=".repeat(60)}\n`);

  const openCmd =
    process.platform === "darwin"
      ? `open ${url}`
      : process.platform === "win32"
        ? `start ${url}`
        : `xdg-open ${url}`;

  exec(openCmd);
});
