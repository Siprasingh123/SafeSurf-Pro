/**
 * SafeSurf Pro - Centralized Scan History & Telemetry Manager
 * Manages persistent scan records, threat stats aggregation, deduplication,
 * and RFC 4180 compliant CSV export across background and dashboard scripts.
 */

const HistoryManager = (() => {
  const MAX_HISTORY_ITEMS = 500;
  const DEDUPLICATION_WINDOW_MS = 5000; // 5 seconds debounce per URL
  let writeQueue = Promise.resolve();

  function isEligibleUrl(urlStr) {
    if (!urlStr || typeof urlStr !== "string") return false;
    try {
      const u = new URL(urlStr);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  function extractDomain(urlStr) {
    try {
      return new URL(urlStr).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function deriveThreatStatus(riskTier, securityScore = 100) {
    if (riskTier === "Critical") return "Critical";
    if (riskTier === "High") return "High";
    if (riskTier === "Medium" || (typeof securityScore === "number" && securityScore < 50)) return "Suspicious";
    return "Safe";
  }

  function recalculateThreatStats(history) {
    const list = Array.isArray(history) ? history : [];
    let safeCount = 0;
    let suspiciousCount = 0;
    let phishingCount = 0;
    let criticalCount = 0;
    let totalSecScore = 0;
    let totalPhishScore = 0;

    for (const item of list) {
      const status = item.threatStatus || deriveThreatStatus(item.riskTier, item.securityScore);
      if (status === "Critical") {
        criticalCount++;
        phishingCount++;
      } else if (status === "High" || status === "Phishing") {
        phishingCount++;
      } else if (status === "Suspicious") {
        suspiciousCount++;
      } else {
        safeCount++;
      }

      totalSecScore += (typeof item.securityScore === "number" ? item.securityScore : 70);
      totalPhishScore += (typeof item.phishingRiskScore === "number" ? item.phishingRiskScore : 0);
    }

    const totalScans = list.length;
    return {
      totalScans,
      safeCount,
      suspiciousCount,
      phishingCount,
      criticalCount,
      avgSecurityScore: totalScans > 0 ? Math.round(totalSecScore / totalScans) : 0,
      avgPhishingRisk: totalScans > 0 ? Math.round(totalPhishScore / totalScans) : 0
    };
  }

  function findRecentDuplicateIndex(recentList, newRecord) {
    if (!recentList || recentList.length === 0) return -1;
    const now = Date.parse(newRecord.timestamp) || Date.now();
    const norm = (u) => String(u || "").trim().toLowerCase().replace(/\/$/, "");
    const targetNorm = norm(newRecord.url);

    // Check top 8 most recent records
    const checkCount = Math.min(8, recentList.length);
    for (let i = 0; i < checkCount; i++) {
      const existing = recentList[i];
      if (norm(existing.url) === targetNorm) {
        const existingTime = Date.parse(existing.timestamp) || 0;
        if (Math.abs(now - existingTime) < DEDUPLICATION_WINDOW_MS) {
          return i;
        }
      }
    }
    return -1;
  }

  function isDuplicate(recentList, newRecord) {
    return findRecentDuplicateIndex(recentList, newRecord) !== -1;
  }

  function createRecord({
    url,
    domain,
    securityScore = 70,
    phishingRiskScore = 0,
    riskTier = "Low",
    findings = [],
    reasons = [],
    threatStatus
  }) {
    const host = domain || extractDomain(url);
    const finalTier = riskTier || (phishingRiskScore >= 75 ? "Critical" : phishingRiskScore >= 50 ? "High" : phishingRiskScore >= 25 ? "Medium" : "Low");
    const finalThreat = threatStatus || deriveThreatStatus(finalTier, securityScore);

    let primaryThreat = "No critical threats detected";
    if (reasons && reasons.length > 0) {
      primaryThreat = typeof reasons[0] === "string" ? reasons[0] : reasons[0].text || reasons[0];
    } else if (findings && findings.length > 0) {
      primaryThreat = findings[0].msg || findings[0];
    }

    // Limit findings and reasons to safeguard local storage quota
    const safeFindings = (Array.isArray(findings) ? findings.slice(0, 15) : []).map(f => ({
      sev: f.sev || "info",
      cat: f.cat || "general",
      msg: String(f.msg || f).slice(0, 300)
    }));

    const safeReasons = (Array.isArray(reasons) ? reasons.slice(0, 15) : []).map(r => ({
      category: r.category || "Signal",
      text: String(r.text || r).slice(0, 300)
    }));

    return {
      id: "scan_" + Date.now() + "_" + Math.random().toString(36).substr(2, 6),
      timestamp: new Date().toISOString(),
      url: String(url || ""),
      domain: host,
      securityScore: Math.min(100, Math.max(0, Math.round(securityScore))),
      phishingRiskScore: Math.min(100, Math.max(0, Math.round(phishingRiskScore))),
      riskTier: finalTier,
      threatStatus: finalThreat,
      findingsCount: safeFindings.length,
      findings: safeFindings,
      reasonsCount: safeReasons.length,
      reasons: safeReasons,
      primaryThreat: String(primaryThreat).slice(0, 300)
    };
  }

  function filterHistoryItems(items, query = "", riskFilter = "ALL") {
    const list = Array.isArray(items) ? items : [];
    const q = (query || "").trim().toLowerCase();
    const rf = (riskFilter || "ALL").toUpperCase();

    return list.filter((item) => {
      const d = (item.domain || "").toLowerCase();
      const u = (item.url || "").toLowerCase();
      const t = (item.primaryThreat || "").toLowerCase();
      const matchesSearch = !q || d.includes(q) || u.includes(q) || t.includes(q);

      const status = item.threatStatus || deriveThreatStatus(item.riskTier, item.securityScore);
      let matchesRisk = true;
      if (rf === "SAFE") {
        matchesRisk = status === "Safe";
      } else if (rf === "SUSPICIOUS") {
        matchesRisk = status === "Suspicious";
      } else if (rf === "PHISHING") {
        matchesRisk = (status === "Phishing" || status === "High" || status === "Critical");
      }

      return matchesSearch && matchesRisk;
    });
  }

  // Atomic sequential write queue to prevent storage overwrite race conditions
  function saveRecord(recordData) {
    if (!isEligibleUrl(recordData?.url)) {
      console.warn("[SafeSurf Pro:History] Skipped ineligible URL:", recordData?.url);
      return Promise.resolve(null);
    }

    const newRecord = createRecord(recordData);

    writeQueue = writeQueue.catch(() => {}).then(async () => {
      try {
        const store = await chrome.storage.local.get(["scan_history", "threat_stats"]);
        const history = Array.isArray(store.scan_history) ? store.scan_history : [];

        const dupIdx = findRecentDuplicateIndex(history, newRecord);
        if (dupIdx !== -1) {
          const existing = history[dupIdx];
          // Check if new record is richer than existing (e.g. content script findings received after premature background scan)
          const isRicher = (newRecord.findingsCount > (existing.findingsCount || 0)) ||
                          (newRecord.reasonsCount > (existing.reasonsCount || 0)) ||
                          (newRecord.threatStatus !== "Safe" && existing.threatStatus === "Safe");

          if (isRicher) {
            history[dupIdx] = newRecord;
            const stats = recalculateThreatStats(history);
            await chrome.storage.local.set({
              scan_history: history,
              threat_stats: stats
            });
            console.log(`[SafeSurf Pro:History] Upgraded scan record with rich DOM data (${newRecord.domain})`);
            return newRecord;
          }

          console.log("[SafeSurf Pro:History] Ignored duplicate scan within window:", newRecord.url);
          return existing;
        }

        history.unshift(newRecord);
        if (history.length > MAX_HISTORY_ITEMS) {
          history.splice(MAX_HISTORY_ITEMS);
        }

        const stats = recalculateThreatStats(history);

        await chrome.storage.local.set({
          scan_history: history,
          threat_stats: stats
        });

        console.log(`[SafeSurf Pro:History] Successfully saved scan record. Total scans: ${stats.totalScans} (${newRecord.domain})`);
        return newRecord;
      } catch (err) {
        console.error("[SafeSurf Pro:History] Failed to write scan record to chrome.storage.local:", err);
        return null;
      }
    });

    return writeQueue;
  }

  async function getHistory() {
    try {
      const store = await chrome.storage.local.get("scan_history");
      return Array.isArray(store.scan_history) ? store.scan_history : [];
    } catch (err) {
      console.error("[SafeSurf Pro:History] Failed to get scan history:", err);
      return [];
    }
  }

  async function getStats() {
    try {
      const store = await chrome.storage.local.get(["scan_history", "threat_stats"]);
      const history = Array.isArray(store.scan_history) ? store.scan_history : [];
      if (store.threat_stats && typeof store.threat_stats.totalScans === "number") {
        return store.threat_stats;
      }
      // Re-synchronize stats if missing or incomplete
      const stats = recalculateThreatStats(history);
      await chrome.storage.local.set({ threat_stats: stats });
      return stats;
    } catch (err) {
      console.error("[SafeSurf Pro:History] Failed to get threat stats:", err);
      return { totalScans: 0, safeCount: 0, suspiciousCount: 0, phishingCount: 0 };
    }
  }

  async function clearHistory() {
    const emptyStats = {
      totalScans: 0,
      safeCount: 0,
      suspiciousCount: 0,
      phishingCount: 0,
      avgSecurityScore: 0,
      avgPhishingRisk: 0
    };
    try {
      await chrome.storage.local.set({
        scan_history: [],
        threat_stats: emptyStats
      });
      console.log("[SafeSurf Pro:History] History and stats cleared successfully.");
      return true;
    } catch (err) {
      console.error("[SafeSurf Pro:History] Failed to clear history:", err);
      return false;
    }
  }

  function exportToCsvString(history) {
    const items = Array.isArray(history) ? history : [];
    const headers = [
      "Timestamp",
      "URL",
      "Domain",
      "Security Score",
      "Phishing Risk Score",
      "Risk Tier",
      "Threat Status",
      "Findings Count",
      "Primary Threat"
    ];

    const escapeCell = (val) => {
      const str = val === null || val === undefined ? "" : String(val);
      return `"${str.replace(/"/g, '""')}"`;
    };

    const rows = [headers.map(escapeCell).join(",")];

    for (const item of items) {
      rows.push([
        escapeCell(item.timestamp),
        escapeCell(item.url),
        escapeCell(item.domain),
        escapeCell(item.securityScore),
        escapeCell(item.phishingRiskScore),
        escapeCell(item.riskTier),
        escapeCell(item.threatStatus || deriveThreatStatus(item.riskTier)),
        escapeCell(item.findingsCount || (item.findings ? item.findings.length : 0)),
        escapeCell(item.primaryThreat)
      ].join(","));
    }

    return rows.join("\r\n");
  }

  return {
    isEligibleUrl,
    extractDomain,
    deriveThreatStatus,
    recalculateThreatStats,
    createRecord,
    saveRecord,
    getHistory,
    getStats,
    clearHistory,
    exportToCsvString,
    filterHistoryItems,
    MAX_HISTORY_ITEMS
  };
})();

if (typeof globalThis !== "undefined") globalThis.HistoryManager = HistoryManager;
if (typeof self !== "undefined") self.HistoryManager = HistoryManager;
if (typeof window !== "undefined") window.HistoryManager = HistoryManager;
if (typeof module !== "undefined" && module.exports) {
  module.exports = HistoryManager;
}
