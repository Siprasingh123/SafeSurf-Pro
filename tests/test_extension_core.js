/**
 * Automated Test Suite for SafeSurf Pro Extension Modules
 * Tests URL analysis, Shannon entropy, homoglyphs, brand spoofing,
 * ML tree evaluation, Explainable AI reasons, and manifest validity.
 */

const fs = require("fs");
const path = require("path");

// Mock Chrome extension APIs for headless unit testing
global.chrome = {
  runtime: {
    getURL: (file) => path.join(__dirname, "..", file)
  },
  storage: {
    local: {
      get: async (k) => ({}),
      set: async (obj) => {}
    },
    session: {
      get: async (k) => ({}),
      set: async (obj) => {}
    }
  }
};

const URLAnalyzer = require("../url_analyzer.js");
const MLEngine = require("../ml_engine.js");

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
  console.log("SAFESURF PRO - AUTOMATED MODULE TESTS");
  console.log("=======================================================\n");

  // 1. Manifest V3 Integrity
  console.log("[Test Suite 1: Manifest V3 Structure]");
  const manifestRaw = fs.readFileSync(path.join(__dirname, "../manifest.json"), "utf8");
  const manifest = JSON.parse(manifestRaw);
  assert(manifest.manifest_version === 3, "Manifest version is 3");
  assert(manifest.name === "SafeSurf Pro", "Manifest name is SafeSurf Pro");
  assert(manifest.background.service_worker === "background.js", "Background service worker configured");
  assert(manifest.permissions.includes("webRequest"), "Permissions contain webRequest");
  assert(manifest.permissions.includes("storage"), "Permissions contain storage");
  assert(manifest.permissions.includes("tabs"), "Permissions contain tabs");
  assert(manifest.permissions.includes("cookies"), "Permissions contain cookies");

  // 2. Shannon Entropy & String Heuristics
  console.log("\n[Test Suite 2: Shannon Entropy & Math]");
  const lowEntropy = URLAnalyzer.shannonEntropy("google.com");
  const highEntropy = URLAnalyzer.shannonEntropy("a8b7c9x0z1q2w3e4.top");
  assert(highEntropy > lowEntropy, `High entropy (${highEntropy}) > Low entropy (${lowEntropy})`);
  assert(URLAnalyzer.shannonEntropy("") === 0, "Empty string has 0 entropy");

  // 3. IP Detection
  console.log("\n[Test Suite 3: IP Address Detection]");
  assert(URLAnalyzer.isIpHost("192.168.1.1"), "Detects standard IPv4 host");
  assert(URLAnalyzer.isIpHost("142.250.190.46:8080"), "Detects IPv4 with port");
  assert(URLAnalyzer.isIpHost("0x7f000001"), "Detects hex IP");
  assert(!URLAnalyzer.isIpHost("google.com"), "Does not flag legitimate domain as IP");

  // 4. Unicode & Homoglyph Normalization
  console.log("\n[Test Suite 4: Homoglyph Normalization]");
  // Cyrillic 'а' (U+0430) vs Latin 'a'
  const cyrillicApple = "\u0430pple";
  const normalized = URLAnalyzer.normalizeHomoglyphs(cyrillicApple);
  assert(normalized === "apple", `Cyrillic '${cyrillicApple}' normalized to '${normalized}'`);

  // 5. Brand Impersonation & Typosquatting
  console.log("\n[Test Suite 5: Brand Typosquatting Detection]");
  const paypalTyposquat = URLAnalyzer.analyze("http://paypa1-security.xyz/login.php");
  assert(paypalTyposquat.isSuspiciousTLD, "Identified suspicious TLD .xyz");
  assert(paypalTyposquat.brandAnalysis.brandSimilarityScore > 0.5, "Detected brand similarity to PayPal");
  assert(paypalTyposquat.reasons.length > 0, "Generated explainable reasons for typosquat");

  const legitGoogle = URLAnalyzer.analyze("https://www.google.com/search?q=test");
  assert(!legitGoogle.isSuspiciousTLD, "Legitimate domain does not trigger suspicious TLD");
  assert(legitGoogle.brandAnalysis.reasons.length === 0, "Official Google domain is whitelisted");
  assert(legitGoogle.isHttps, "HTTPS is true for secure site");

  // 6. ML Feature Vector Consistency
  console.log("\n[Test Suite 6: Feature Vector Size & Types]");
  assert(paypalTyposquat.features.length === 20, `Feature vector has exactly 20 features (got ${paypalTyposquat.features.length})`);
  assert(paypalTyposquat.features.every(v => typeof v === "number" && !isNaN(v)), "All features are valid numbers");

  // 7. Client-Side ML Model Inference & Explainable AI
  console.log("\n[Test Suite 7: Client-Side Machine Learning Model]");
  const modelJsonRaw = fs.readFileSync(path.join(__dirname, "../models/phishing_model.json"), "utf8");
  const modelJson = JSON.parse(modelJsonRaw);
  assert(modelJson.trees.length > 0, `Loaded JSON model with ${modelJson.trees.length} trees`);

  // Inject model into MLEngine
  MLEngine.setModel(modelJson);

  // Test phishing features
  const phishFeatures = [...paypalTyposquat.features];
  phishFeatures[17] = 1; // external form action
  phishFeatures[18] = 1; // password present
  phishFeatures[19] = 2; // phishing keywords

  const phishPred = await MLEngine.predict(phishFeatures);
  assert(phishPred.riskScore >= 50, `Phishing risk score is high: ${phishPred.riskScore}/100`);
  assert(phishPred.isPhishing, "ML model predicted isPhishing = true");
  assert(phishPred.explanations.length > 0, `Explainable AI produced ${phishPred.explanations.length} reasons`);

  // Test legitimate features
  const legitFeatures = [...legitGoogle.features];
  const legitPred = await MLEngine.predict(legitFeatures);
  assert(legitPred.riskScore < 30, `Legitimate site risk score is low: ${legitPred.riskScore}/100`);
  assert(!legitPred.isPhishing, "ML model predicted isPhishing = false for legitimate site");

  // Summary
  console.log("\n=======================================================");
  console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log("=======================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
