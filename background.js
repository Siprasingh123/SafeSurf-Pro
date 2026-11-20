/**
 * SafeSurf Pro - Background Service Worker & Security Orchestrator
 * Integrates WebRequest headers, URL heuristics, ML inference, Google Safe Browsing,
 * history logging, and optional active blocking while preserving core functionality.
 */

try {
  importScripts("models/phishing_model.js", "url_analyzer.js", "ml_engine.js", "safe_browsing.js", "history.js");
  console.log("[SafeSurf Pro:BG] Worker helper scripts imported successfully.");
} catch (e) {
  console.error("[SafeSurf Pro:BG] Error importing service worker scripts:", e);
}

// 1. Capture Security Headers on main_frame navigation (Preserves existing feature)
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.type !== "main_frame" || !d.url || !d.url.startsWith("http")) return;
    const h = {};
    for (const x of d.responseHeaders || []) {
      h[x.name.toLowerCase()] = x.value || "";
    }
    const csp = h["content-security-policy"] || "";
    const data = {
      url: d.url,
      statusCode: d.statusCode,
      hsts: !!h["strict-transport-security"],
      csp: !!csp,
      xfo: !!h["x-frame-options"] || /frame-ancestors/i.test(csp),
      nosniff: (h["x-content-type-options"] || "").toLowerCase() === "nosniff",
      referrer: !!h["referrer-policy"]
    };

    try {
      chrome.storage.session.set({ ["hdr_" + d.tabId]: data });
    } catch (e) {
      console.warn("[SafeSurf Pro:BG] Session storage set error on headers:", e);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Calculate Website Security Score (0 - 100) based on HTTPS, Headers, and Cookies
function calculateSecurityScore(url, headers, cookieStats = null) {
  let score = 0;
  let isHttps = false;

  try {
    const parsed = new URL(url);
    if (parsed.protocol === "https:") {
      score += 30;
      isHttps = true;
    }
  } catch {}

  if (headers) {
    if (isHttps && headers.hsts) score += 15;
    if (headers.csp) score += 20;
    if (headers.xfo) score += 15;
    if (headers.nosniff) score += 10;
    if (headers.referrer) score += 5;
  } else if (isHttps) {
    score += 20; // Default baseline for encrypted transport when headers unavailable
  }

  // Cookie security contribution (up to 5 points)
  if (cookieStats) {
    if (cookieStats.total === 0 || cookieStats.insecure === 0) {
      score += 5;
    }
  } else {
    score += 5;
  }

  return Math.min(100, Math.max(0, score));
}

// Unified Scan Processing Pipeline
async function processScan(pageUrl, tabId, domMeta = {}, findings = [], thirdParty = []) {
  if (!HistoryManager.isEligibleUrl(pageUrl)) {
    return null;
  }

  console.log(`[SafeSurf Pro:BG] Processing scan for: ${pageUrl} (Tab: ${tabId})`);

  // Retrieve temporary headers from session storage (with origin validation)
  let headers = null;
  try {
    const headerStore = await chrome.storage.session.get("hdr_" + tabId);
    const cachedHeaders = headerStore["hdr_" + tabId];
    if (cachedHeaders) {
      try {
        if (new URL(cachedHeaders.url).origin === new URL(pageUrl).origin) {
          headers = cachedHeaders;
        } else {
          console.debug(`[SafeSurf Pro:BG] Discarded mismatched cached headers for ${pageUrl}`);
        }
      } catch {
        if (cachedHeaders.url === pageUrl) headers = cachedHeaders;
      }
    }
  } catch (err) {
    console.debug("[SafeSurf Pro:BG] Session headers read fallback:", err);
  }

  // Retrieve cookies and analyze security posture (Secure, HttpOnly flags)
  let cookieStats = { total: 0, insecure: 0 };
  try {
    const cookies = await chrome.cookies.getAll({ url: pageUrl });
    if (Array.isArray(cookies)) {
      cookieStats.total = cookies.length;
      cookieStats.insecure = cookies.filter(c => !c.secure || !c.httpOnly).length;
      if (cookieStats.total > 0 && cookieStats.insecure > 0) {
        findings.push({
          sev: "med",
          cat: "cookies",
          msg: `Cookie Security: ${cookieStats.insecure} of ${cookieStats.total} cookie(s) lack Secure or HttpOnly protection.`
        });
      }
    }
  } catch (err) {
    console.debug("[SafeSurf Pro:BG] Cookie inspection fallback:", err);
  }

  // 1. Calculate Comprehensive Website Security Score
  const securityScore = calculateSecurityScore(pageUrl, headers, cookieStats);

  // 2. Perform Advanced URL Analysis
  const urlAnalysis = URLAnalyzer.analyze(pageUrl) || {
    features: new Array(20).fill(0),
    reasons: [],
    brandAnalysis: { brandSimilarityScore: 0, reasons: [] },
    isIp: false,
    isPunycode: false,
    isSuspiciousTLD: false
  };

  // 3. Assemble ML feature vector (20 features)
  const features = [...urlAnalysis.features];
  if (domMeta) {
    features[17] = domMeta.external_form_action ? 1 : 0;
    features[18] = domMeta.password_field_present ? 1 : 0;
    features[19] = domMeta.phishing_keyword_count || 0;
  }

  // 4. Client-Side Machine Learning Prediction
  const mlResult = await MLEngine.predict(features);

  // 5. Threat Intelligence (Google Safe Browsing API)
  const safeBrowsingResult = await SafeBrowsing.checkUrl(pageUrl);

  // 6. Synthesize Phishing Risk Score & Explainable AI Reasons
  let phishingRiskScore = mlResult.riskScore;
  const reasons = [];

  for (const r of urlAnalysis.reasons) {
    reasons.push({ category: "URL & Domain", text: r });
  }

  for (const f of findings) {
    reasons.push({ category: "Page Content", text: f.msg });
    if (f.sev === "high") phishingRiskScore = Math.min(100, phishingRiskScore + 15);
  }

  for (const expl of mlResult.explanations) {
    if (!reasons.some(r => r.text === expl)) {
      reasons.push({ category: "AI Detection", text: expl });
    }
  }

  if (safeBrowsingResult.flagged) {
    phishingRiskScore = 100;
    reasons.unshift({
      category: "Threat Intelligence",
      text: `Google Safe Browsing Match: ${safeBrowsingResult.threatTypes.join(", ")}`
    });
  }

  let finalRiskTier = "Low";
  if (phishingRiskScore >= 75) finalRiskTier = "Critical";
  else if (phishingRiskScore >= 50) finalRiskTier = "High";
  else if (phishingRiskScore >= 25) finalRiskTier = "Medium";

  const comprehensiveScan = {
    tabId,
    url: pageUrl,
    timestamp: new Date().toISOString(),
    securityScore,
    phishingRiskScore,
    riskTier: finalRiskTier,
    threatStatus: HistoryManager.deriveThreatStatus(finalRiskTier, securityScore),
    isPhishing: finalRiskTier === "Critical" || finalRiskTier === "High",
    findings: findings || [],
    thirdParty: thirdParty || [],
    cookieStats,
    headers: headers || null,
    urlAnalysis,
    mlResult,
    safeBrowsing: safeBrowsingResult,
    reasons
  };

  // Cache per-tab active scan in session storage for popup UI
  try {
    await chrome.storage.session.set({
      ["scan_" + tabId]: comprehensiveScan
    });
  } catch (err) {
    console.warn("[SafeSurf Pro:BG] Session storage set error:", err);
  }

  // Update Chrome Action Badge
  try {
    if (finalRiskTier === "Critical" || finalRiskTier === "High") {
      chrome.action.setBadgeText({ tabId, text: "!" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#d93025" });
    } else if (finalRiskTier === "Medium" || securityScore < 50) {
      chrome.action.setBadgeText({ tabId, text: "WARN" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
    } else {
      chrome.action.setBadgeText({ tabId, text: "OK" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#188038" });
    }
  } catch (err) {
    console.debug("[SafeSurf Pro:BG] Badge update error:", err);
  }

  // Save to persistent History in chrome.storage.local
  const savedRecord = await HistoryManager.saveRecord({
    url: pageUrl,
    domain: HistoryManager.extractDomain(pageUrl),
    securityScore,
    phishingRiskScore,
    riskTier: finalRiskTier,
    threatStatus: HistoryManager.deriveThreatStatus(finalRiskTier, securityScore),
    findings,
    reasons
  });

  // Check optional active blocking with user bypass support
  try {
    const settings = await chrome.storage.local.get("blocking_enabled");
    const bypassStore = await chrome.storage.session.get("bypass_" + tabId).catch(() => ({}));
    const isBypassed = bypassStore && bypassStore["bypass_" + tabId] === pageUrl;

    if (settings.blocking_enabled && (finalRiskTier === "Critical" || finalRiskTier === "High") && !isBypassed) {
      const blockUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(pageUrl)}&score=${phishingRiskScore}&reason=${encodeURIComponent(reasons[0]?.text || "Suspected Phishing")}`
      );
      chrome.tabs.update(tabId, { url: blockUrl });
    } else if (finalRiskTier === "Critical" || finalRiskTier === "High" || finalRiskTier === "Medium") {
      chrome.tabs.sendMessage(tabId, {
        type: "SHOW_PASSIVE_ALERT",
        riskTier: finalRiskTier,
        isBypassed: !!isBypassed,
        reasons: reasons.map(r => r.text)
      }).catch(() => {});
    }
  } catch (err) {
    console.debug("[SafeSurf Pro:BG] Alert dispatch error:", err);
  }

  return comprehensiveScan;
}

// 2. Message Listener (Must return true to keep async port open in Manifest V3)
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;

  if (msg.type === "scan") {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    const pageUrl = msg.url || (sender.tab ? sender.tab.url : "");

    if (!pageUrl || !tabId) {
      sendResponse({ success: false, error: "Missing tab or URL" });
      return true;
    }

    processScan(pageUrl, tabId, msg.meta, msg.findings, msg.thirdParty)
      .then((scanResult) => {
        sendResponse({ success: true, result: scanResult });
      })
      .catch((err) => {
        console.error("[SafeSurf Pro:BG] Error in scan handler:", err);
        sendResponse({ success: false, error: String(err) });
      });

    return true; // Keep service worker alive for async response
  }

  if (msg.type === "REQUEST_SCAN") {
    const tabId = msg.tabId;
    const pageUrl = msg.url;
    if (!pageUrl || !tabId) {
      sendResponse({ success: false });
      return true;
    }

    // Attempt to query content script for rich DOM data first
    chrome.tabs.sendMessage(tabId, { type: "REQUEST_PAGE_SCAN" }, (response) => {
      if (!chrome.runtime.lastError && response?.data) {
        processScan(pageUrl, tabId, response.data.meta, response.data.findings, response.data.thirdParty)
          .then((res) => sendResponse({ success: true, result: res }))
          .catch((err) => sendResponse({ success: false, error: String(err) }));
      } else {
        processScan(pageUrl, tabId)
          .then((res) => sendResponse({ success: true, result: res }))
          .catch((err) => sendResponse({ success: false, error: String(err) }));
      }
    });

    return true;
  }

  if (msg.type === "ALLOW_BYPASS") {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    if (tabId && msg.url) {
      chrome.storage.session.set({ ["bypass_" + tabId]: msg.url }).then(() => {
        sendResponse({ success: true });
      }).catch(() => sendResponse({ success: false }));
      return true;
    }
    sendResponse({ success: false });
    return true;
  }
});

// 3. Tab Navigation Observer (Ensures every eligible website is scanned without duplicate scans or stale cache)
const tabScanDebounce = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const targetUrl = changeInfo.url || tab?.url;
  if (!targetUrl || !HistoryManager.isEligibleUrl(targetUrl)) return;

  // When a new navigation starts, invalidate old cached tab scan/header session data
  if (changeInfo.url) {
    try {
      chrome.storage.session.remove(["scan_" + tabId, "hdr_" + tabId]);
      chrome.storage.session.get("bypass_" + tabId).then((bStore) => {
        if (bStore && bStore["bypass_" + tabId] !== changeInfo.url) {
          chrome.storage.session.remove("bypass_" + tabId);
        }
      });
    } catch {}
  }

  // Only consider fallback after page loading is complete
  if (changeInfo.status === "complete") {
    if (tabScanDebounce.has(tabId)) {
      clearTimeout(tabScanDebounce.get(tabId));
    }

    const timer = setTimeout(async () => {
      tabScanDebounce.delete(tabId);
      try {
        const store = await chrome.storage.session.get("scan_" + tabId);
        const existingScan = store["scan_" + tabId];
        // If content script already completed scan for this URL, no fallback needed
        if (existingScan && existingScan.url === targetUrl) {
          return;
        }

        // Query content script first
        chrome.tabs.sendMessage(tabId, { type: "REQUEST_PAGE_SCAN" }, (response) => {
          if (!chrome.runtime.lastError && response?.data) {
            processScan(targetUrl, tabId, response.data.meta, response.data.findings, response.data.thirdParty).catch(() => {});
          } else {
            console.log(`[SafeSurf Pro:BG] Executing background fallback scan for tab ${tabId} (${targetUrl})`);
            processScan(targetUrl, tabId).catch((err) => {
              console.debug("[SafeSurf Pro:BG] Tab update background scan error:", err);
            });
          }
        });
      } catch (err) {
        console.debug("[SafeSurf Pro:BG] Tab scan check error:", err);
      }
    }, 700);

    tabScanDebounce.set(tabId, timer);
  }
});

// 4. Cleanup on tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
  try {
    chrome.storage.session.remove(["hdr_" + tabId, "scan_" + tabId]);
  } catch {}
});

// 5. Worker lifecycle startup initialization
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[SafeSurf Pro:BG] Extension installed or updated. Verifying storage state...");
  await HistoryManager.getStats();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log("[SafeSurf Pro:BG] Browser startup. Validating scan telemetry...");
  await HistoryManager.getStats();
});
