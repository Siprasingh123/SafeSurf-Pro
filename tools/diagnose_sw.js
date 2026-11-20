/**
 * Diagnostic v3: Properly attach to SW and check for startup errors.
 * Uses CDP's Target.attachToTarget to get the real SW context.
 */
const http = require("http");
const WebSocket = require("ws");
const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const EXT_DIR = path.resolve(__dirname, "..");
const CDP_PORT = 9336;
const PROFILE_DIR = path.join(os.tmpdir(), "safesurf_diag3_" + Date.now());

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function cdpListTargets() {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${CDP_PORT}/json`, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => { try { resolve(JSON.parse(data)); } catch { reject(data); } });
    }).on("error", reject);
  });
}

// Full duplex CDP session on a target
class CDPSession {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.ws = null;
    this.id = 0;
    this.callbacks = {};
    this.events = [];
  }

  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.on("open", () => resolve());
      this.ws.on("message", (msg) => {
        const data = JSON.parse(msg.toString());
        if (data.id && this.callbacks[data.id]) {
          this.callbacks[data.id](data);
          delete this.callbacks[data.id];
        }
        if (data.method) {
          this.events.push(data);
        }
      });
      this.ws.on("error", reject);
    });
  }

  async send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.callbacks[id] = resolve;
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.callbacks[id]) {
          delete this.callbacks[id];
          reject(new Error(`Timeout for ${method}`));
        }
      }, 15000);
    });
  }

  close() { try { this.ws.close(); } catch {} }
}

async function main() {
  console.log("\n=== SafeSurf Pro Diagnostic v3 ===\n");

  try { execSync(`taskkill /F /IM chrome.exe 2>nul`, { stdio: "ignore" }); } catch {}
  await sleep(1500);
  if (fs.existsSync(PROFILE_DIR)) fs.rmSync(PROFILE_DIR, { recursive: true, force: true });

  const chrome = spawn(CHROME_PATH, [
    `--load-extension=${EXT_DIR}`,
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${PROFILE_DIR}`,
    "--no-first-run", "--no-default-browser-check", "--disable-default-apps",
    "--disable-sync",
    "--disable-extensions-except=" + EXT_DIR,
    "https://github.com"  // Navigate directly to a real site
  ], { stdio: "pipe", windowsHide: true });

  for (let i = 0; i < 20; i++) {
    await sleep(1000);
    try { const t = await cdpListTargets(); if (t.length > 0) break; } catch {}
  }

  // Wait extra time for page load + content script + scan processing
  console.log("Waiting 12s for full page load and scan processing...");
  await sleep(12000);

  let targets = await cdpListTargets();
  console.log("All targets:");
  targets.forEach(t => console.log(`  [${t.type}] ${t.url?.substring(0, 120)}`));

  // Find our SW
  let sw = targets.find(t => t.type === "service_worker" && t.url && t.url.includes("background.js"));
  if (!sw) {
    console.log("\n!! background.js service worker NOT FOUND !!");
    // Check if SW crashed
    // Maybe the importScripts failed and killed the SW

    // Let's check if the extension page shows errors
    // Navigate a page to chrome://extensions
    let page = targets.find(t => t.type === "page");
    if (page) {
      const session = new CDPSession(page.webSocketDebuggerUrl);
      await session.connect();

      // Navigate to extensions page to check for errors  
      await session.send("Page.navigate", { url: "chrome://extensions" });
      await sleep(3000);

      const result = await session.send("Runtime.evaluate", {
        expression: `document.querySelector('extensions-manager')?.shadowRoot?.querySelector('#viewManager extensions-item-list')?.shadowRoot?.querySelectorAll('extensions-item').length`,
        returnByValue: true
      });
      console.log("  Extensions found:", result?.result?.result?.value);
      session.close();
    }
    cleanup(chrome);
    return;
  }

  console.log(`\nOur SW: ${sw.url}`);

  // Connect CDP session to our SW
  const session = new CDPSession(sw.webSocketDebuggerUrl);
  await session.connect();

  // Enable runtime and console
  await session.send("Runtime.enable");

  // Check globals
  console.log("\n--- Checking globals in SW context ---");
  const globalChecks = {
    "typeof HistoryManager": "HistoryManager",
    "typeof URLAnalyzer": "URLAnalyzer", 
    "typeof MLEngine": "MLEngine",
    "typeof SafeBrowsing": "SafeBrowsing",
    "typeof PHISHING_MODEL": "PHISHING_MODEL",
    "typeof processScan": "processScan",
    "typeof chrome": "chrome",
    "typeof chrome?.storage": "chrome.storage",
    "typeof chrome?.storage?.local": "chrome.storage.local",
    "typeof chrome?.runtime": "chrome.runtime",
    "typeof chrome?.tabs": "chrome.tabs",
  };

  for (const [expr, label] of Object.entries(globalChecks)) {
    try {
      const res = await session.send("Runtime.evaluate", {
        expression: expr,
        returnByValue: true
      });
      console.log(`  ${label}: ${res?.result?.result?.value || res?.result?.exceptionDetails?.exception?.description || JSON.stringify(res?.result)}`);
    } catch (e) {
      console.log(`  ${label}: ERROR ${e.message}`);
    }
  }

  // Check storage directly
  console.log("\n--- Checking chrome.storage.local ---");
  try {
    const res = await session.send("Runtime.evaluate", {
      expression: `new Promise(resolve => { if(chrome && chrome.storage && chrome.storage.local) { chrome.storage.local.get(null, resolve); } else { resolve({__error:'chrome.storage.local not available'}); }})`,
      returnByValue: true,
      awaitPromise: true
    });
    const data = res?.result?.result?.value;
    console.log("  Full storage keys:", Object.keys(data || {}));
    console.log("  scan_history:", Array.isArray(data?.scan_history) ? `${data.scan_history.length} records` : "N/A");
    console.log("  threat_stats:", JSON.stringify(data?.threat_stats));
    if (data?.scan_history?.length > 0) {
      data.scan_history.forEach((r, i) => {
        console.log(`    [${i}] ${r.domain} sec=${r.securityScore} risk=${r.phishingRiskScore} status=${r.threatStatus}`);
      });
    }
  } catch (e) {
    console.log("  Storage error:", e.message);
  }

  // Try manual processScan 
  console.log("\n--- Manual processScan from correct SW ---");
  try {
    const res = await session.send("Runtime.evaluate", {
      expression: `(async () => {
        if (typeof processScan !== 'function') {
          // Check self
          const fns = Object.getOwnPropertyNames(self).filter(n => typeof self[n] === 'function');
          return JSON.stringify({err:'processScan not a function', selfFunctions: fns.slice(0, 20), hasChrome: typeof chrome, hasSelf: typeof self});
        }
        const r = await processScan("https://example.com", 99999);
        return JSON.stringify({ok:true, sec:r?.securityScore, risk:r?.phishingRiskScore});
      })()`,
      returnByValue: true,
      awaitPromise: true
    });
    console.log("  Result:", res?.result?.result?.value || JSON.stringify(res?.result));
  } catch (e) {
    console.log("  Error:", e.message);
  }

  // Check all execution contexts  
  console.log("\n--- Execution contexts ---");
  // Collect any Runtime.executionContextCreated events
  const ctxEvents = session.events.filter(e => e.method === "Runtime.executionContextCreated");
  ctxEvents.forEach(e => {
    const ctx = e.params?.context;
    console.log(`  Context ${ctx?.id}: name="${ctx?.name}" origin="${ctx?.origin}"`);
  });

  session.close();

  // Also check the content script on the github page
  console.log("\n--- Checking content script on page ---");
  let page = targets.find(t => t.type === "page" && t.url?.includes("github"));
  if (page) {
    const pageSess = new CDPSession(page.webSocketDebuggerUrl);
    await pageSess.connect();
    await pageSess.send("Runtime.enable");
    
    // Wait for contexts
    await sleep(1000);
    
    // Check if content script ran
    try {
      const res = await pageSess.send("Runtime.evaluate", {
        expression: `document.getElementById('safesurf-alert-banner') ? 'banner exists' : 'no banner (normal for safe sites)'`,
        returnByValue: true
      });
      console.log("  Banner check:", res?.result?.result?.value);
    } catch (e) {
      console.log("  Banner check error:", e.message);
    }

    pageSess.close();
  } else {
    console.log("  No GitHub page target found");
  }

  console.log("\n=== Diagnostic v3 Complete ===");
  cleanup(chrome);
}

function cleanup(chrome) {
  try { chrome.kill(); } catch {}
  try { execSync(`taskkill /F /IM chrome.exe 2>nul`, { stdio: "ignore" }); } catch {}
  setTimeout(() => {
    try { fs.rmSync(PROFILE_DIR, { recursive: true, force: true }); } catch {}
    process.exit(0);
  }, 2000);
}

main().catch(e => { console.error(e); process.exit(1); });
