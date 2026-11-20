/**
 * SafeSurf Pro - Live Data Collection & Persistence Integration Test Suite
 * Tests scan recording, deduplication, stats aggregation, CSV export,
 * and simulations for GitHub, testphp.vulnweb.com, and phishing URLs.
 */

const fs = require("fs");
const path = require("path");

// In-memory mock of chrome.storage.local & chrome.storage.session
const mockStorage = {
  local: {},
  session: {},
  listeners: []
};

global.chrome = {
  runtime: {
    getURL: (file) => path.join(__dirname, "..", file),
    lastError: null
  },
  storage: {
    local: {
      get: async (keys) => {
        if (!keys) return { ...mockStorage.local };
        const keyList = Array.isArray(keys) ? keys : [keys];
        const res = {};
        for (const k of keyList) {
          if (mockStorage.local[k] !== undefined) {
            res[k] = JSON.parse(JSON.stringify(mockStorage.local[k]));
          }
        }
        return res;
      },
      set: async (items) => {
        const changes = {};
        for (const k in items) {
          changes[k] = {
            oldValue: mockStorage.local[k],
            newValue: JSON.parse(JSON.stringify(items[k]))
          };
          mockStorage.local[k] = JSON.parse(JSON.stringify(items[k]));
        }
        mockStorage.listeners.forEach((fn) => fn(changes, "local"));
      }
    },
    session: {
      get: async (keys) => {
        if (!keys) return { ...mockStorage.session };
        const keyList = Array.isArray(keys) ? keys : [keys];
        const res = {};
        for (const k of keyList) {
          if (mockStorage.session[k] !== undefined) res[k] = mockStorage.session[k];
        }
        return res;
      },
      set: async (items) => {
        for (const k in items) mockStorage.session[k] = items[k];
      },
      remove: async (keys) => {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) delete mockStorage.session[k];
      }
    },
    onChanged: {
      addListener: (fn) => mockStorage.listeners.push(fn)
    }
  }
};

const HistoryManager = require("../history.js");
const URLAnalyzer = require("../url_analyzer.js");
const MLEngine = require("../ml_engine.js");

// Initialize ML model
const modelJson = JSON.parse(fs.readFileSync(path.join(__dirname, "../models/phishing_model.json"), "utf8"));
MLEngine.setModel(modelJson);

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  \x1b[32m✔ PASS:\x1b[0m ${message}`);
    passed++;
  } else {
    console.error(`  \x1b[31m✖ FAIL:\x1b[0m ${message}`);
    failed++;
  }
}

async function runTests() {
  console.log("\n=======================================================");
  console.log("SAFESURF PRO - LIVE DATA PERSISTENCE TESTS");
  console.log("=======================================================\n");

  // 1. Initial State
  console.log("[Test 1: Initial Empty Storage State]");
  let stats = await HistoryManager.getStats();
  assert(stats.totalScans === 0, "Initial totalScans is 0");
  assert(stats.safeCount === 0, "Initial safeCount is 0");
  let history = await HistoryManager.getHistory();
  assert(history.length === 0, "Initial history array is empty");

  // 2. Test Eligible vs Ineligible URLs
  console.log("\n[Test 2: URL Eligibility Filtering]");
  assert(HistoryManager.isEligibleUrl("https://github.com"), "GitHub is an eligible URL");
  assert(HistoryManager.isEligibleUrl("http://testphp.vulnweb.com/login.php"), "Vulnweb is an eligible URL");
  assert(!HistoryManager.isEligibleUrl("chrome://extensions"), "chrome:// is filtered out");
  assert(!HistoryManager.isEligibleUrl("chrome-extension://abcdef/dashboard.html"), "Extension pages filtered out");
  assert(!HistoryManager.isEligibleUrl("about:blank"), "about:blank is filtered out");

  const nullRecord = await HistoryManager.saveRecord({ url: "chrome://settings" });
  assert(nullRecord === null, "Ineligible URL produces no storage write");

  // 3. Simulate GitHub Scan (Legitimate Site)
  console.log("\n[Test 3: Simulate Legitimate Site (GitHub)]");
  const githubAnalysis = URLAnalyzer.analyze("https://github.com/login");
  const ghFeatures = [...githubAnalysis.features];
  ghFeatures[18] = 1; // password field present
  const ghMl = await MLEngine.predict(ghFeatures);

  const ghRecord = await HistoryManager.saveRecord({
    url: "https://github.com/login",
    domain: "github.com",
    securityScore: 95,
    phishingRiskScore: ghMl.riskScore,
    riskTier: ghMl.riskTier,
    threatStatus: "Safe",
    findings: [],
    reasons: []
  });

  assert(ghRecord !== null, "GitHub scan record created");
  assert(ghRecord.domain === "github.com", "Domain extracted as github.com");
  assert(ghRecord.threatStatus === "Safe", "GitHub threatStatus marked Safe");
  assert(ghRecord.phishingRiskScore < 30, `GitHub phishing risk is low (${ghRecord.phishingRiskScore}/100)`);

  stats = await HistoryManager.getStats();
  assert(stats.totalScans === 1, `Total scans incremented to 1 (got ${stats.totalScans})`);
  assert(stats.safeCount === 1, `Safe count is 1 (got ${stats.safeCount})`);

  // 4. Test Deduplication
  console.log("\n[Test 4: Deduplication on Rapid Re-navigation]");
  const dupRecord = await HistoryManager.saveRecord({
    url: "https://github.com/login",
    domain: "github.com",
    securityScore: 95,
    phishingRiskScore: ghMl.riskScore,
    riskTier: ghMl.riskTier,
    threatStatus: "Safe"
  });
  assert(dupRecord === null, "Duplicate scan within 5s was ignored");
  stats = await HistoryManager.getStats();
  assert(stats.totalScans === 1, "Total scans remain 1 after duplicate attempt");

  // 5. Simulate http://testphp.vulnweb.com (Vulnerable / Insecure HTTP Login)
  console.log("\n[Test 5: Simulate Insecure/Suspicious Site (testphp.vulnweb.com)]");
  const vulnUrl = "http://testphp.vulnweb.com/login.php";
  const vulnAnalysis = URLAnalyzer.analyze(vulnUrl);
  const vulnFeatures = [...vulnAnalysis.features];
  vulnFeatures[16] = 0; // HTTP unencrypted
  vulnFeatures[18] = 1; // Password on HTTP
  const vulnMl = await MLEngine.predict(vulnFeatures);

  const vulnRecord = await HistoryManager.saveRecord({
    url: vulnUrl,
    domain: "testphp.vulnweb.com",
    securityScore: 35, // low security due to HTTP and lack of HSTS/CSP
    phishingRiskScore: Math.max(35, vulnMl.riskScore),
    riskTier: "Medium",
    threatStatus: "Suspicious",
    findings: [
      { sev: "high", msg: "Password field found on an unencrypted (HTTP) page." }
    ],
    reasons: [
      { category: "Security Posture", text: "Unencrypted connection (HTTP)" }
    ]
  });

  assert(vulnRecord !== null, "testphp.vulnweb.com scan record created");
  assert(vulnRecord.threatStatus === "Suspicious", "Status marked Suspicious");
  assert(vulnRecord.findings.length > 0, "Suspicious findings captured");
  stats = await HistoryManager.getStats();
  assert(stats.totalScans === 2, `Total scans incremented to 2 (got ${stats.totalScans})`);
  assert(stats.suspiciousCount === 1, `Suspicious count incremented to 1 (got ${stats.suspiciousCount})`);

  // 6. Simulate Local Phishing Simulation Page (Typosquatting & Fake Form)
  console.log("\n[Test 6: Simulate Phishing Attack Page]");
  const phishUrl = "http://paypa1-account-verify.xyz/login.php";
  const phishAnalysis = URLAnalyzer.analyze(phishUrl);
  const phishFeatures = [...phishAnalysis.features];
  phishFeatures[17] = 1; // external form action
  phishFeatures[18] = 1; // password field
  phishFeatures[19] = 2; // urgent keywords
  const phishMl = await MLEngine.predict(phishFeatures);

  const phishRecord = await HistoryManager.saveRecord({
    url: phishUrl,
    domain: "paypa1-account-verify.xyz",
    securityScore: 20,
    phishingRiskScore: phishMl.riskScore,
    riskTier: phishMl.riskTier,
    threatStatus: "Phishing",
    findings: [
      { sev: "high", msg: "A form sends its data to another site" }
    ],
    reasons: phishAnalysis.reasons
  });

  assert(phishRecord !== null, "Phishing record created");
  assert(phishRecord.threatStatus === "Phishing", "ThreatStatus flagged as Phishing");
  assert(phishRecord.phishingRiskScore >= 75, `Phishing risk score is critical (${phishRecord.phishingRiskScore}/100)`);
  stats = await HistoryManager.getStats();
  assert(stats.totalScans === 3, `Total scans is 3 (got ${stats.totalScans})`);
  assert(stats.phishingCount === 1, `Phishing count is 1 (got ${stats.phishingCount})`);

  // 7. Verify History Retrieval & Storage Persistence
  console.log("\n[Test 7: Persistence Verification across Session/ServiceWorker]");
  history = await HistoryManager.getHistory();
  assert(history.length === 3, `History contains exactly 3 records (got ${history.length})`);
  assert(history[0].domain === "paypa1-account-verify.xyz", "Most recent scan is at head of list");
  assert(history[1].domain === "testphp.vulnweb.com", "Second scan is vulnweb");
  assert(history[2].domain === "github.com", "Third scan is GitHub");

  // Verify all required fields from Requirement 8
  const sample = history[0];
  assert(sample.timestamp !== undefined, "Record has timestamp");
  assert(sample.url !== undefined, "Record has url");
  assert(sample.domain !== undefined, "Record has domain");
  assert(sample.securityScore !== undefined, "Record has securityScore");
  assert(sample.phishingRiskScore !== undefined, "Record has phishingRiskScore");
  assert(sample.findings !== undefined, "Record has findings");
  assert(sample.threatStatus !== undefined, "Record has threatStatus");

  // 8. Test CSV Export Format
  console.log("\n[Test 8: CSV Export Generator]");
  const csv = HistoryManager.exportToCsvString(history);
  assert(csv.includes("Timestamp") && csv.includes("Domain") && csv.includes("URL"), "CSV has header row");
  assert(csv.includes("github.com"), "CSV includes github.com");
  assert(csv.includes("testphp.vulnweb.com"), "CSV includes vulnweb");
  assert(csv.includes("paypa1-account-verify.xyz"), "CSV includes phishing domain");
  const lineCount = csv.split("\r\n").length;
  assert(lineCount === 4, `CSV has 1 header + 3 rows = 4 lines (got ${lineCount})`);

  // 9. Test Clear History
  console.log("\n[Test 9: Clear History]");
  const cleared = await HistoryManager.clearHistory();
  assert(cleared === true, "clearHistory returned true");
  stats = await HistoryManager.getStats();
  assert(stats.totalScans === 0, "Stats totalScans reset to 0");
  assert(stats.safeCount === 0, "Stats safeCount reset to 0");
  assert(stats.suspiciousCount === 0, "Stats suspiciousCount reset to 0");
  assert(stats.phishingCount === 0, "Stats phishingCount reset to 0");
  history = await HistoryManager.getHistory();
  assert(history.length === 0, "History is empty after clear");

  console.log("\n=======================================================");
  console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("=======================================================\n");

  if (failed > 0) process.exit(1);
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
