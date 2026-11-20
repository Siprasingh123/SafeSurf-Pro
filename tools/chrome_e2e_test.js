/**
 * SafeSurf Pro - Real Chrome E2E Test
 * Launches Chrome with the extension, navigates to real sites,
 * and verifies scan records reach chrome.storage.local.
 */

const http = require("http");
const { execSync, spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const EXT_DIR = path.resolve(__dirname, "..");
const CDP_PORT = 9333;
const PROFILE_DIR = path.join(os.tmpdir(), "safesurf_e2e_test_" + Date.now());

let chromeProc = null;
let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  ✔ PASS: ${msg}`);
    passed++;
  } else {
    console.log(`  ✘ FAIL: ${msg}`);
    failed++;
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// CDP helper: send command via HTTP
async function cdpRequest(target, method, params = {}) {
  const body = JSON.stringify({ id: 1, method, params });
  return new Promise((resolve, reject) => {
    const req = http.request(
      `http://127.0.0.1:${CDP_PORT}${target}`,
      { method: "PUT", headers: { "Content-Type": "application/json" } },
      (res) => {
        let data = "";
        res.on("data", c => data += c);
        res.on("end", () => {
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// List all CDP targets
async function cdpListTargets() {
  return new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${CDP_PORT}/json`, (res) => {
      let data = "";
      res.on("data", c => data += c);
      res.on("end", () => {
        try { resolve(JSON.parse(data)); } catch { reject(new Error("Parse error: " + data)); }
      });
    }).on("error", reject);
  });
}

// Evaluate JS expression in a target via CDP HTTP endpoint
async function cdpEval(wsUrl, expression, awaitPromise = false) {
  // Use the /json/version endpoint style doesn't work for eval
  // Instead use WebSocket-based CDP
  const WebSocket = (() => {
    try { return require("ws"); } catch { return null; }
  })();
  
  if (!WebSocket) {
    // Fallback: use http endpoint  
    // Actually we need WS for Runtime.evaluate. Let's try a different approach.
    // Use the target's debugger URL with a raw HTTP POST won't work.
    // Instead, let's navigate and check storage via a special page approach.
    return null;
  }
  
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let id = 1;
    ws.on("open", () => {
      ws.send(JSON.stringify({
        id: id,
        method: "Runtime.evaluate",
        params: { expression, returnByValue: true, awaitPromise }
      }));
    });
    ws.on("message", (msg) => {
      try {
        const resp = JSON.parse(msg.toString());
        if (resp.id === id) {
          ws.close();
          resolve(resp.result);
        }
      } catch {}
    });
    ws.on("error", reject);
    setTimeout(() => { try { ws.close(); } catch {} reject(new Error("CDP eval timeout")); }, 10000);
  });
}

// Check if ws module is available
function hasWsModule() {
  try { require("ws"); return true; } catch { return false; }
}

async function main() {
  console.log("\n=======================================================");
  console.log("SAFESURF PRO - REAL CHROME E2E TEST");
  console.log("=======================================================\n");

  // Kill any existing Chrome processes on our debug port
  try { execSync(`taskkill /F /IM chrome.exe 2>nul`, { stdio: "ignore" }); } catch {}
  await sleep(1000);

  // Ensure clean profile
  if (fs.existsSync(PROFILE_DIR)) {
    fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
  }

  console.log("[Setup] Launching Chrome with extension...");
  console.log(`  Extension: ${EXT_DIR}`);
  console.log(`  Profile: ${PROFILE_DIR}`);
  console.log(`  CDP Port: ${CDP_PORT}`);

  chromeProc = spawn(CHROME_PATH, [
    `--load-extension=${EXT_DIR}`,
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${PROFILE_DIR}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-background-networking",
    "--disable-extensions-except=" + EXT_DIR,
    "about:blank"
  ], { stdio: "pipe", windowsHide: true });

  chromeProc.on("error", (err) => console.error("[Chrome] Launch error:", err));

  // Wait for Chrome to start and CDP to be available
  let cdpReady = false;
  for (let attempt = 0; attempt < 20; attempt++) {
    await sleep(1000);
    try {
      const targets = await cdpListTargets();
      if (targets && targets.length > 0) {
        cdpReady = true;
        break;
      }
    } catch {}
  }

  if (!cdpReady) {
    console.error("[FATAL] Chrome CDP not available after 20s. Aborting.");
    cleanup();
    process.exit(1);
  }

  console.log("[Setup] Chrome launched and CDP available.\n");

  // === Test 1: Find Extension Service Worker ===
  console.log("[Test 1: Service Worker Detection]");
  await sleep(3000); // Give SW time to start

  let targets = await cdpListTargets();
  let swTarget = targets.find(t => 
    t.type === "service_worker" && t.url && t.url.includes("background.js")
  );
  
  // Also check for extension page target
  let extTargets = targets.filter(t => 
    t.url && t.url.startsWith("chrome-extension://")
  );

  assert(extTargets.length > 0, `Found ${extTargets.length} extension target(s)`);
  
  // Get extension ID from any extension target
  let extensionId = null;
  for (const t of targets) {
    if (t.url && t.url.startsWith("chrome-extension://")) {
      const m = t.url.match(/chrome-extension:\/\/([^/]+)/);
      if (m) { extensionId = m[1]; break; }
    }
  }
  
  if (swTarget) {
    assert(true, `Service worker found: ${swTarget.url}`);
    if (!extensionId) {
      const m = swTarget.url.match(/chrome-extension:\/\/([^/]+)/);
      if (m) extensionId = m[1];
    }
  } else {
    // SW may have spawned and gone idle. Check later.
    assert(false, "Service worker target not immediately visible (may be idle)");
  }

  console.log(`  Extension ID: ${extensionId || "unknown"}`);

  // === Test 2: Navigate to a real website and trigger scan ===
  console.log("\n[Test 2: Navigate to GitHub]");
  
  // Find the about:blank page target
  let pageTarget = targets.find(t => t.type === "page" && t.url === "about:blank");
  if (!pageTarget) {
    pageTarget = targets.find(t => t.type === "page");
  }

  if (!pageTarget) {
    console.log("  No page target found. Targets:", targets.map(t => `${t.type}: ${t.url}`));
    assert(false, "Page target found for navigation");
  } else {
    assert(true, `Page target found: ${pageTarget.url}`);

    // Check if we have ws module for CDP eval
    const hasWs = hasWsModule();
    console.log(`  WebSocket module (ws): ${hasWs ? "Available" : "Not available - will use alternative approach"}`);

    if (hasWs) {
      // Navigate to GitHub
      const navResult = await cdpEval(
        pageTarget.webSocketDebuggerUrl,
        `window.location.href = "https://github.com"; "navigating"`,
        false
      );
      console.log(`  Navigation initiated: ${navResult?.result?.value}`);
      
      // Wait for page load and content script scan
      await sleep(8000);

      // Re-fetch targets to find the service worker (it should have woken up)
      targets = await cdpListTargets();
      swTarget = targets.find(t => 
        t.type === "service_worker" && t.url && t.url.includes("background.js")
      );

      if (swTarget) {
        console.log("  Service worker active after navigation.");
        
        // === Test 3: Check chrome.storage.local for scan records ===
        console.log("\n[Test 3: Verify Scan Records in Storage]");
        
        const storageResult = await cdpEval(
          swTarget.webSocketDebuggerUrl,
          `new Promise(resolve => chrome.storage.local.get(["scan_history", "threat_stats"], resolve))`,
          true
        );

        if (storageResult && storageResult.result && storageResult.result.value) {
          const storageData = storageResult.result.value;
          const history = storageData.scan_history || [];
          const stats = storageData.threat_stats || {};

          console.log(`  Storage data retrieved. History: ${history.length} records, Stats:`, stats);

          assert(history.length > 0, `Scan history has ${history.length} record(s) (expected >= 1)`);
          assert(stats.totalScans > 0, `Total scans counter: ${stats.totalScans}`);

          if (history.length > 0) {
            const first = history[0];
            assert(!!first.url, `Record has URL: ${first.url}`);
            assert(!!first.domain, `Record has domain: ${first.domain}`);
            assert(typeof first.securityScore === "number", `Record has securityScore: ${first.securityScore}`);
            assert(typeof first.phishingRiskScore === "number", `Record has phishingRiskScore: ${first.phishingRiskScore}`);
            assert(!!first.threatStatus, `Record has threatStatus: ${first.threatStatus}`);
            assert(!!first.timestamp, `Record has timestamp: ${first.timestamp}`);
            assert(first.domain.includes("github"), `Domain is github-related: ${first.domain}`);
          }

          // === Test 4: Navigate to second site ===
          console.log("\n[Test 4: Navigate to httpbin.org]");
          
          // Navigate to a second site via the page target
          // Find updated page target
          targets = await cdpListTargets();
          pageTarget = targets.find(t => t.type === "page" && t.url && t.url.includes("github"));
          if (!pageTarget) {
            pageTarget = targets.find(t => t.type === "page" && !t.url.startsWith("chrome"));
          }

          if (pageTarget) {
            await cdpEval(
              pageTarget.webSocketDebuggerUrl,
              `window.location.href = "https://httpbin.org"; "navigating"`,
              false
            );
            
            await sleep(8000);

            // Re-check storage via SW
            targets = await cdpListTargets();
            swTarget = targets.find(t =>
              t.type === "service_worker" && t.url && t.url.includes("background.js")
            );

            if (swTarget) {
              const storageResult2 = await cdpEval(
                swTarget.webSocketDebuggerUrl,
                `new Promise(resolve => chrome.storage.local.get(["scan_history", "threat_stats"], resolve))`,
                true
              );

              if (storageResult2 && storageResult2.result && storageResult2.result.value) {
                const data2 = storageResult2.result.value;
                const history2 = data2.scan_history || [];
                const stats2 = data2.threat_stats || {};

                assert(history2.length >= 2, `History has ${history2.length} records after 2 navigations`);
                assert(stats2.totalScans >= 2, `Total scans: ${stats2.totalScans}`);
              }
            }
          }

          // === Test 5: Persistence - re-read storage ===
          console.log("\n[Test 5: Persistence Verification]");
          targets = await cdpListTargets();
          swTarget = targets.find(t =>
            t.type === "service_worker" && t.url && t.url.includes("background.js")
          );

          if (swTarget) {
            const persistResult = await cdpEval(
              swTarget.webSocketDebuggerUrl,
              `new Promise(resolve => chrome.storage.local.get(["scan_history", "threat_stats"], resolve))`,
              true
            );

            if (persistResult && persistResult.result && persistResult.result.value) {
              const pd = persistResult.result.value;
              assert(pd.scan_history && pd.scan_history.length > 0, "History persists across reads");
              assert(pd.threat_stats && pd.threat_stats.totalScans > 0, "Stats persist across reads");
            }
          }
        } else {
          console.log("  Storage result:", JSON.stringify(storageResult));
          assert(false, "Could not read chrome.storage.local via CDP");
        }
      } else {
        console.log("  Available targets:", targets.map(t => `${t.type}: ${t.url?.substring(0, 80)}`).join("\n    "));
        assert(false, "Service worker found after navigation");
      }
    } else {
      // Without ws module, we can only verify targets exist
      console.log("\n  [Note] 'ws' npm module not installed. Cannot evaluate JS via CDP.");
      console.log("  Performing target-only verification...\n");
      
      // We can still verify targets by navigating via a temp HTML page approach
      // or by checking that the extension loaded correctly
      
      assert(extensionId !== null, "Extension loaded with valid ID");
      assert(extTargets.length >= 1, "Extension has active targets");
      
      console.log("\n  To run full E2E tests, install ws: npm install ws");
    }
  }

  // === Test 6: Dashboard page loads ===
  console.log("\n[Test 6: Dashboard Page Load]");
  if (extensionId && hasWsModule()) {
    // Navigate to dashboard
    targets = await cdpListTargets();
    pageTarget = targets.find(t => t.type === "page" && !t.url.startsWith("chrome-extension"));
    if (!pageTarget) pageTarget = targets.find(t => t.type === "page");

    if (pageTarget) {
      const dashUrl = `chrome-extension://${extensionId}/dashboard.html`;
      await cdpEval(
        pageTarget.webSocketDebuggerUrl,
        `window.location.href = "${dashUrl}"; "navigating"`,
        false
      );
      
      await sleep(3000);
      
      targets = await cdpListTargets();
      const dashTarget = targets.find(t => t.type === "page" && t.url && t.url.includes("dashboard.html"));
      
      if (dashTarget) {
        assert(true, "Dashboard page target found");
        
        const domResult = await cdpEval(
          dashTarget.webSocketDebuggerUrl,
          `JSON.stringify({
            statTotal: document.getElementById("statTotal")?.textContent,
            statSafe: document.getElementById("statSafe")?.textContent,
            historyCount: document.getElementById("historyCount")?.textContent,
            pieChart: document.getElementById("pieChartSvg")?.children?.length,
            barChart: document.getElementById("barChartSvg")?.children?.length
          })`,
          false
        );

        if (domResult && domResult.result && domResult.result.value) {
          const dom = JSON.parse(domResult.result.value);
          console.log("  Dashboard DOM values:", dom);
          
          const totalNum = parseInt(dom.statTotal);
          assert(!isNaN(totalNum) && totalNum > 0, `Dashboard total scans counter: ${dom.statTotal}`);
          assert(dom.pieChart > 0, `Donut chart has ${dom.pieChart} SVG elements`);
          assert(dom.barChart > 0, `Bar chart has ${dom.barChart} SVG elements`);
          assert(dom.historyCount && !dom.historyCount.includes("0 entries"), `History count: ${dom.historyCount}`);
        }
      } else {
        assert(false, "Dashboard page loaded");
      }
    }
  } else {
    console.log("  Skipped (requires ws module and extension ID)");
  }

  // Print summary
  console.log("\n=======================================================");
  console.log(`E2E TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("=======================================================\n");

  cleanup();
  process.exit(failed > 0 ? 1 : 0);
}

function cleanup() {
  console.log("[Cleanup] Shutting down Chrome...");
  if (chromeProc) {
    try { chromeProc.kill(); } catch {}
    try { execSync(`taskkill /F /IM chrome.exe 2>nul`, { stdio: "ignore" }); } catch {}
  }
  // Clean profile after short delay
  setTimeout(() => {
    try {
      if (fs.existsSync(PROFILE_DIR)) {
        fs.rmSync(PROFILE_DIR, { recursive: true, force: true });
      }
    } catch {}
  }, 2000);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
process.on("uncaughtException", (err) => {
  console.error("[Fatal]", err);
  cleanup();
  process.exit(1);
});

main().catch((err) => {
  console.error("[Fatal]", err);
  cleanup();
  process.exit(1);
});
