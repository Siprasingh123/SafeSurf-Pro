const { spawn } = require("child_process");
const http = require("http");
const path = require("path");

const CHROME_PATH = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const EXTENSION_DIR = path.resolve(__dirname, "..");
const USER_DATA_DIR = path.resolve(__dirname, "temp-sw-test");
const PORT = 9223;

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(JSON.parse(data)));
    }).on("error", reject);
  });
}

async function testSW() {
  const chromeArgs = [
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${USER_DATA_DIR}`,
    `--load-extension=${EXTENSION_DIR}`,
    `--disable-extensions-except=${EXTENSION_DIR}`,
    "--no-sandbox",
    "--disable-gpu",
    "about:blank"
  ];

  const proc = spawn(CHROME_PATH, chromeArgs);

  for (let i = 0; i < 30; i++) {
    try {
      await fetchJson(`http://127.0.0.1:${PORT}/json/version`);
      break;
    } catch {
      await delay(300);
    }
  }

  const targets = await fetchJson(`http://127.0.0.1:${PORT}/json/list`);
  const sw = targets.find(t => t.type === "service_worker" && t.url.includes("background.js"));

  console.log("Service Worker target:", sw?.url);
  if (!sw) {
    console.error("NO SERVICE WORKER FOUND!");
    proc.kill();
    return;
  }

  const ws = new WebSocket(sw.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);

  function evaluate(expr) {
    return new Promise((resolve) => {
      const id = Math.floor(Math.random() * 100000);
      const onMsg = (evt) => {
        const msg = JSON.parse(evt.data);
        if (msg.id === id) {
          ws.removeEventListener("message", onMsg);
          resolve(msg.result?.result);
        }
      };
      ws.addEventListener("message", onMsg);
      ws.send(JSON.stringify({
        id,
        method: "Runtime.evaluate",
        params: { expression: expr, awaitPromise: true, returnByValue: true }
      }));
    });
  }

  console.log("URLAnalyzer:", await evaluate("typeof URLAnalyzer"));
  console.log("MLEngine:", await evaluate("typeof MLEngine"));
  console.log("HistoryManager:", await evaluate("typeof HistoryManager"));
  console.log("PHISHING_MODEL:", await evaluate("typeof PHISHING_MODEL"));
  console.log("Manifest:", await evaluate("chrome.runtime.getManifest().name"));

  // Now test processScan directly in Chrome!
  console.log("\nCalling processScan('https://github.com/login', 1) in Chrome...");
  const scanRes = await evaluate("processScan('https://github.com/login', 1)");
  console.log("Scan result:", scanRes?.value ? "SUCCESS" : scanRes);

  const storage = await evaluate("chrome.storage.local.get(null)");
  console.log("Storage after scan:", JSON.stringify(storage?.value, null, 2));

  ws.close();
  proc.kill();
}

testSW().catch(console.error);
