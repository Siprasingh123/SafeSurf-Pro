/**
 * Real Chrome End-to-End Browser Test
 * Launches actual Chrome with SafeSurf Pro loaded, navigates to real pages,
 * inspects Service Worker console, and verifies live Dashboard DOM updates via CDP.
 */

const { spawn } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const EXTENSION_DIR = path.resolve(__dirname, "..");
const USER_DATA_DIR = path.resolve(__dirname, "temp-test-profile");
const PORT = 9222;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on("error", reject);
  });
}

class SimpleCDP {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.id = 1;
    this.callbacks = new Map();
  }

  async connect() {
    const WebSocket = global.WebSocket || require("ws");
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onopen = resolve;
      this.ws.onerror = reject;
      this.ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.id && this.callbacks.has(msg.id)) {
          const cb = this.callbacks.get(msg.id);
          this.callbacks.delete(msg.id);
          if (msg.error) cb.reject(msg.error);
          else cb.resolve(msg.result);
        }
      };
    });
  }

  send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.id++;
      this.callbacks.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

async function runEndToEndTest() {
  console.log("=======================================================");
  console.log("SAFESURF PRO - REAL CHROME END-TO-END TEST");
  console.log("=======================================================\n");

  if (fs.existsSync(USER_DATA_DIR)) {
    try { fs.rmSync(USER_DATA_DIR, { recursive: true, force: true }); } catch {}
  }

  console.log("[Chrome] Spawning real Chrome with SafeSurf Pro extension...");
  const chromeArgs = [
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${USER_DATA_DIR}`,
    `--load-extension=${EXTENSION_DIR}`,
    `--disable-extensions-except=${EXTENSION_DIR}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-features=Translate",
    "--no-sandbox",
    "--disable-gpu",
    "about:blank"
  ];

  const chromeProc = spawn(CHROME_PATH, chromeArgs, { stdio: "pipe" });
  chromeProc.stdout.on("data", (d) => console.log("[Chrome STDOUT]", d.toString().trim()));
  chromeProc.stderr.on("data", (d) => console.log("[Chrome STDERR]", d.toString().trim()));
  chromeProc.on("exit", (code) => console.log("[Chrome Exit Code]", code));

  try {
    // Wait for Chrome CDP to be available
    console.log("[Chrome] Waiting for remote debugging port...");
    let connected = false;
    for (let i = 0; i < 40; i++) {
      try {
        await fetchJson(`http://127.0.0.1:${PORT}/json/version`);
        connected = true;
        break;
      } catch (e) {
        if (i % 5 === 0) console.log(`[Connecting attempt ${i}]`, e.message);
        await delay(500);
      }
    }

    if (!connected) {
      throw new Error("Could not connect to Chrome debugging port 9222");
    }
    console.log("✔ Connected to Chrome remote debugging port.\n");

    // Discover targets
    const targets = await fetchJson(`http://127.0.0.1:${PORT}/json/list`);
    console.log(`[Targets] Discovered ${targets.length} targets in Chrome:`);
    targets.forEach(t => console.log(`  - [${t.type}] ${t.title || t.url}`));

    // Find extension ID from service worker or manifest
    let serviceWorkerTarget = targets.find(t => t.type === "service_worker" && t.url.includes("background.js"));
    let extId = "";
    if (serviceWorkerTarget) {
      const match = serviceWorkerTarget.url.match(/chrome-extension:\/\/([a-p0-9]+)\//);
      if (match) extId = match[1];
      console.log(`\n✔ Identified SafeSurf Pro Extension ID: ${extId}`);
    }

    // Connect to Service Worker to check logs and errors
    let swCdp = null;
    if (serviceWorkerTarget) {
      swCdp = new SimpleCDP(serviceWorkerTarget.webSocketDebuggerUrl);
      await swCdp.connect();
      console.log("✔ Connected to Background Service Worker via CDP.");

      swCdp.ws.addEventListener("message", (evt) => {
        const msg = JSON.parse(evt.data);
        if (msg.method === "Runtime.consoleAPICalled") {
          const args = (msg.params.args || []).map(a => a.value || a.description).join(" ");
          console.log(`[SW Console ${msg.params.type}]`, args);
        }
        if (msg.method === "Runtime.exceptionThrown") {
          console.error("[SW Exception]", msg.params.exceptionDetails?.text, msg.params.exceptionDetails?.exception?.description);
        }
      });
      await swCdp.send("Runtime.enable");

      // Check storage state inside service worker
      const storageState = await swCdp.send("Runtime.evaluate", {
        expression: "chrome.storage.local.get(['scan_history', 'threat_stats'])",
        awaitPromise: true,
        returnByValue: true
      });
      console.log("[Service Worker] Initial Storage State:", storageState.result?.value);
    }

    // Open Page 1: Legitimate site (GitHub)
    console.log("\n[Navigation 1] Navigating tab to https://github.com/ ...");
    let pageTarget = targets.find(t => t.type === "page");
    if (!pageTarget) {
      const newTab = await fetchJson(`http://127.0.0.1:${PORT}/json/new?https://github.com/`);
      pageTarget = newTab;
    } else {
      const pageCdp = new SimpleCDP(pageTarget.webSocketDebuggerUrl);
      await pageCdp.connect();
      await pageCdp.send("Page.navigate", { url: "https://github.com/" });
      pageCdp.close();
    }

    // Wait 3 seconds for scan to complete and save
    console.log("[Scan] Waiting for GitHub scan and local storage persistence...");
    await delay(3500);

    // Re-check service worker storage
    const swCdp2 = new SimpleCDP(serviceWorkerTarget.webSocketDebuggerUrl);
    await swCdp2.connect();
    const swStorageAfterGH = await swCdp2.send("Runtime.evaluate", {
      expression: "chrome.storage.local.get(null)",
      awaitPromise: true,
      returnByValue: true
    });
    console.log("[Service Worker] Storage After GitHub:", JSON.stringify(swStorageAfterGH.result?.value, null, 2));
    swCdp2.close();

    // Open Page 2: Insecure site (http://testphp.vulnweb.com/)
    console.log("\n[Navigation 2] Navigating tab to http://testphp.vulnweb.com/ ...");
    const pageCdp2 = new SimpleCDP(pageTarget.webSocketDebuggerUrl);
    await pageCdp2.connect();
    await pageCdp2.send("Page.navigate", { url: "http://testphp.vulnweb.com/" });
    pageCdp2.close();

    console.log("[Scan] Waiting for testphp.vulnweb.com scan and local storage persistence...");
    await delay(3500);

    // Open Dashboard Page using chrome.tabs.create inside Service Worker
    console.log(`\n[Dashboard] Creating privileged tab for dashboard.html ...`);
    const tabRes = await swCdp.send("Runtime.evaluate", {
      expression: "chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).then(t => t.id)",
      awaitPromise: true,
      returnByValue: true
    });
    console.log("[Dashboard] Created tab ID:", tabRes.result?.value);
    await delay(2500);

    // Find the dashboard tab target
    const currentTargets = await fetchJson(`http://127.0.0.1:${PORT}/json/list`);
    const dashTarget = currentTargets.find(t => t.url.includes("dashboard.html"));
    if (!dashTarget) {
      throw new Error("Could not find dashboard.html target in Chrome");
    }

    console.log("[Dashboard] Found dashboard target:", dashTarget.url);
    const dashCdp = new SimpleCDP(dashTarget.webSocketDebuggerUrl);
    await dashCdp.connect();

    dashCdp.ws.addEventListener("message", (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.method === "Runtime.consoleAPICalled") {
        const args = (msg.params.args || []).map(a => a.value || a.description).join(" ");
        console.log(`[Dash Console ${msg.params.type}]`, args);
      }
      if (msg.method === "Runtime.exceptionThrown") {
        console.error("[Dash Exception]", msg.params.exceptionDetails?.text, msg.params.exceptionDetails?.exception?.description);
      }
    });
    await dashCdp.send("Runtime.enable");
    await delay(1000);

    // Inspect Real DOM inside Chrome Dashboard
    console.log("[DOM Verification] Reading live dashboard DOM elements from real Chrome:");
    const domEval = await dashCdp.send("Runtime.evaluate", {
      expression: `({
        statTotal: document.getElementById('statTotal')?.textContent,
        statSafe: document.getElementById('statSafe')?.textContent,
        statSuspicious: document.getElementById('statSuspicious')?.textContent,
        statPhishing: document.getElementById('statPhishing')?.textContent,
        tableRows: document.querySelectorAll('#historyTableBody tr').length,
        firstDomain: document.querySelector('#historyTableBody tr strong')?.textContent,
        historyCount: document.getElementById('historyCount')?.textContent
      })`,
      returnByValue: true
    });

    const dashData = domEval.result?.value;
    console.log("-------------------------------------------------------");
    console.log("REAL CHROME DASHBOARD DOM VALUES:");
    console.log("  Total Scanned:       ", dashData?.statTotal);
    console.log("  Safe Websites:       ", dashData?.statSafe);
    console.log("  Suspicious Sites:    ", dashData?.statSuspicious);
    console.log("  Phishing Threats:    ", dashData?.statPhishing);
    console.log("  History Table Rows:  ", dashData?.tableRows);
    console.log("  First Domain Listed: ", dashData?.firstDomain);
    console.log("  History Counter:     ", dashData?.historyCount);
    console.log("-------------------------------------------------------\n");

    dashCdp.close();

    const totalNum = parseInt(dashData?.statTotal || "0", 10);
    if (totalNum > 0 && dashData?.tableRows > 0) {
      console.log(`\x1b[32m✔ SUCCESS: Real Chrome verified! Dashboard recorded ${totalNum} live website scans!\x1b[0m\n`);
    } else {
      console.error("\x1b[31m✖ FAILURE: Dashboard still shows 0 in real Chrome.\x1b[0m\n");
      process.exitCode = 1;
    }
  } catch (err) {
    console.error("Test error:", err);
    process.exitCode = 1;
  } finally {
    try { chromeProc.kill(); } catch {}
    try { fs.rmSync(USER_DATA_DIR, { recursive: true, force: true }); } catch {}
  }
}

runEndToEndTest();
