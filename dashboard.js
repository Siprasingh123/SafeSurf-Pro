/**
 * SafeSurf Pro - Advanced Threat Intelligence Dashboard
 * Manages scan telemetry, visual SVG charts, history filtering,
 * CSV export, and Google Safe Browsing API key configuration.
 * Real-time reactivity via chrome.storage.onChanged.
 */

const $ = (id) => document.getElementById(id);

let currentHistory = [];
let currentStats = {
  totalScans: 0,
  safeCount: 0,
  suspiciousCount: 0,
  phishingCount: 0
};

// Safe DOM element helper
function createElementWithText(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = text;
  if (className) el.className = className;
  return el;
}

// 1. Theme Configuration
async function initTheme() {
  const store = await chrome.storage.local.get("theme_preference");
  if (store.theme_preference === "dark") {
    document.body.classList.add("dark-theme");
  } else if (store.theme_preference === "light") {
    document.body.classList.add("light-theme");
  }

  $("themeToggleBtn").addEventListener("click", async () => {
    const isDark = document.body.classList.contains("dark-theme") ||
      (!document.body.classList.contains("light-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);

    if (isDark) {
      document.body.classList.remove("dark-theme");
      document.body.classList.add("light-theme");
      await chrome.storage.local.set({ theme_preference: "light" });
    } else {
      document.body.classList.remove("light-theme");
      document.body.classList.add("dark-theme");
      await chrome.storage.local.set({ theme_preference: "dark" });
    }
  });
}

// 2. Settings Management
async function initSettings() {
  const store = await chrome.storage.local.get(["safe_browsing_api_key", "blocking_enabled"]);

  if (store.safe_browsing_api_key) {
    $("apiKeyInput").value = store.safe_browsing_api_key;
  }

  const blockToggle = $("dashBlockingToggle");
  blockToggle.checked = !!store.blocking_enabled;

  blockToggle.addEventListener("change", async () => {
    await chrome.storage.local.set({ blocking_enabled: blockToggle.checked });
  });

  $("saveApiKeyBtn").addEventListener("click", async () => {
    const key = $("apiKeyInput").value.trim();
    await chrome.storage.local.set({ safe_browsing_api_key: key });
    alert("Google Safe Browsing API key saved securely.");
  });
}

// 3. Render Visual SVG Donut Chart
function renderDonutChart(safe, suspicious, phishing) {
  const svg = $("pieChartSvg");
  svg.replaceChildren();

  const total = safe + suspicious + phishing;
  const legend = $("pieLegend");
  legend.replaceChildren();

  if (total === 0) {
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", "110");
    circle.setAttribute("cy", "110");
    circle.setAttribute("r", "75");
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke", "#94a3b8");
    circle.setAttribute("stroke-width", "30");
    circle.setAttribute("opacity", "0.2");
    svg.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", "110");
    text.setAttribute("y", "115");
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", "#94a3b8");
    text.setAttribute("font-size", "12");
    text.textContent = "No scan data yet";
    svg.appendChild(text);
    return;
  }

  const radius = 75;
  const circumference = 2 * Math.PI * radius;
  let accumulatedPercent = 0;

  const slices = [
    { label: "Safe", count: safe, color: "#10b981" },
    { label: "Suspicious", count: suspicious, color: "#f59e0b" },
    { label: "Phishing", count: phishing, color: "#ef4444" }
  ];

  for (const s of slices) {
    if (s.count === 0) continue;
    const percent = s.count / total;
    const strokeDash = `${percent * circumference} ${circumference}`;
    const offset = -(accumulatedPercent * circumference);

    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", "110");
    circle.setAttribute("cy", "110");
    circle.setAttribute("r", radius.toString());
    circle.setAttribute("fill", "none");
    circle.setAttribute("stroke", s.color);
    circle.setAttribute("stroke-width", "30");
    circle.setAttribute("stroke-dasharray", strokeDash);
    circle.setAttribute("stroke-dashoffset", offset.toString());
    circle.setAttribute("transform", "rotate(-90 110 110)");
    svg.appendChild(circle);

    accumulatedPercent += percent;

    const item = createElementWithText("span", `\u25A0 ${s.label}: ${s.count}`);
    item.style.color = s.color;
    item.style.fontWeight = "600";
    legend.appendChild(item);
  }

  const centerText = document.createElementNS("http://www.w3.org/2000/svg", "text");
  centerText.setAttribute("x", "110");
  centerText.setAttribute("y", "108");
  centerText.setAttribute("text-anchor", "middle");
  centerText.setAttribute("font-size", "22");
  centerText.setAttribute("font-weight", "bold");
  centerText.setAttribute("fill", "currentColor");
  centerText.textContent = total.toString();
  svg.appendChild(centerText);

  const centerSub = document.createElementNS("http://www.w3.org/2000/svg", "text");
  centerSub.setAttribute("x", "110");
  centerSub.setAttribute("y", "125");
  centerSub.setAttribute("text-anchor", "middle");
  centerSub.setAttribute("font-size", "11");
  centerSub.setAttribute("fill", "#64748b");
  centerSub.textContent = "Total Scans";
  svg.appendChild(centerSub);
}

// 4. Render Visual SVG Bar Chart
function renderBarChart(recentHistory) {
  const svg = $("barChartSvg");
  svg.replaceChildren();

  const entries = recentHistory.slice(0, 8).reverse();
  if (entries.length === 0) {
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", "225");
    text.setAttribute("y", "100");
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", "#94a3b8");
    text.setAttribute("font-size", "12");
    text.textContent = "Browse websites to generate live risk comparison telemetry.";
    svg.appendChild(text);
    return;
  }

  const svgWidth = 450;
  const barWidth = 16;
  const gap = (svgWidth - 40) / entries.length;

  const baseLine = document.createElementNS("http://www.w3.org/2000/svg", "line");
  baseLine.setAttribute("x1", "20");
  baseLine.setAttribute("y1", "160");
  baseLine.setAttribute("x2", "440");
  baseLine.setAttribute("y2", "160");
  baseLine.setAttribute("stroke", "#64748b");
  baseLine.setAttribute("stroke-width", "1");
  svg.appendChild(baseLine);

  entries.forEach((entry, idx) => {
    const x = 25 + idx * gap;
    const secScore = typeof entry.securityScore === "number" ? entry.securityScore : 70;
    const phishScore = typeof entry.phishingRiskScore === "number" ? entry.phishingRiskScore : 0;

    const secH = Math.max(4, (secScore / 100) * 130);
    const phishH = Math.max(4, (phishScore / 100) * 130);

    // Security Score Bar (Green)
    const secBar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    secBar.setAttribute("x", x.toString());
    secBar.setAttribute("y", (160 - secH).toString());
    secBar.setAttribute("width", barWidth.toString());
    secBar.setAttribute("height", secH.toString());
    secBar.setAttribute("rx", "3");
    secBar.setAttribute("fill", "#10b981");
    svg.appendChild(secBar);

    // Phishing Risk Bar (Red/Orange)
    const phishBar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    phishBar.setAttribute("x", (x + barWidth + 3).toString());
    phishBar.setAttribute("y", (160 - phishH).toString());
    phishBar.setAttribute("width", barWidth.toString());
    phishBar.setAttribute("height", phishH.toString());
    phishBar.setAttribute("rx", "3");
    phishBar.setAttribute("fill", phishScore >= 50 ? "#ef4444" : "#f59e0b");
    svg.appendChild(phishBar);

    // Domain Label
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", (x + barWidth).toString());
    label.setAttribute("y", "175");
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("font-size", "9");
    label.setAttribute("fill", "#64748b");
    const domainShort = (entry.domain || "site").slice(0, 6);
    label.textContent = domainShort;
    svg.appendChild(label);
  });
}

// 5. Render History Table
function renderHistoryTable(items) {
  const tbody = $("historyTableBody");
  tbody.replaceChildren();

  if (!items || items.length === 0) {
    const tr = document.createElement("tr");
    const td = createElementWithText(
      "td",
      "No matching scan history records found.",
      "empty-state"
    );
    td.setAttribute("colspan", "6");
    tr.appendChild(td);
    tbody.appendChild(tr);
    $("historyCount").textContent = "0 entries";
    return;
  }

  $("historyCount").textContent = `${items.length} entr${items.length === 1 ? "y" : "ies"}`;

  for (const item of items) {
    const tr = document.createElement("tr");

    // Timestamp
    const dateStr = item.timestamp ? new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : "Recently";
    tr.appendChild(createElementWithText("td", dateStr));

    // Domain / URL
    const domainTd = document.createElement("td");
    const domainLink = createElementWithText("strong", item.domain || item.url);
    domainLink.title = item.url;
    domainTd.appendChild(domainLink);
    tr.appendChild(domainTd);

    // Security Score
    const secTd = createElementWithText("td", `${item.securityScore !== undefined ? item.securityScore : 70}/100`);
    secTd.style.fontWeight = "600";
    secTd.style.color = (item.securityScore >= 70) ? "var(--good)" : "var(--mid)";
    tr.appendChild(secTd);

    // Phishing Risk
    const phishTd = createElementWithText("td", `${item.phishingRiskScore !== undefined ? item.phishingRiskScore : 0}/100`);
    phishTd.style.fontWeight = "700";
    phishTd.style.color = (item.phishingRiskScore >= 50) ? "var(--bad)" : (item.phishingRiskScore >= 25) ? "var(--mid)" : "var(--good)";
    tr.appendChild(phishTd);

    // Status Badge
    const statusTd = document.createElement("td");
    const tier = item.riskTier || "Low";
    const status = item.threatStatus || HistoryManager.deriveThreatStatus(tier);
    const badge = createElementWithText("span", status, "badge");
    if (status === "Phishing" || status === "High" || status === "Critical") badge.classList.add("badge-phishing");
    else if (status === "Suspicious") badge.classList.add("badge-suspicious");
    else badge.classList.add("badge-safe");
    statusTd.appendChild(badge);
    tr.appendChild(statusTd);

    // Primary Threat / Finding
    const threatTd = createElementWithText("td", item.primaryThreat || "Verified Clean");
    threatTd.style.color = "var(--text-secondary)";
    threatTd.style.maxWidth = "280px";
    threatTd.style.overflow = "hidden";
    threatTd.style.textOverflow = "ellipsis";
    threatTd.style.whiteSpace = "nowrap";
    threatTd.title = item.primaryThreat || "";
    tr.appendChild(threatTd);

    tbody.appendChild(tr);
  }
}

// 6. Search & Filter
function filterHistory() {
  const query = $("searchInput") ? $("searchInput").value : "";
  const riskFilter = $("riskFilter") ? $("riskFilter").value : "ALL";

  const filtered = (typeof HistoryManager !== "undefined" && HistoryManager.filterHistoryItems)
    ? HistoryManager.filterHistoryItems(currentHistory, query, riskFilter)
    : currentHistory;

  renderHistoryTable(filtered);
}

// 7. CSV Export
function exportToCsv() {
  if (!currentHistory || currentHistory.length === 0) {
    alert("No scan history to export.");
    return;
  }

  const csvContent = HistoryManager.exportToCsvString(currentHistory);
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `safesurf_scan_history_${Date.now()}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// 8. Clear History
async function clearHistory() {
  if (!confirm("Are you sure you want to clear all scan history and reset threat statistics?")) {
    return;
  }

  await HistoryManager.clearHistory();
  currentHistory = [];
  currentStats = { totalScans: 0, safeCount: 0, suspiciousCount: 0, phishingCount: 0 };
  updateUI();
}

function updateUI() {
  const total = currentStats?.totalScans ?? currentHistory.length;
  const safe = currentStats?.safeCount ?? 0;
  const suspicious = currentStats?.suspiciousCount ?? 0;
  const phishing = currentStats?.phishingCount ?? 0;

  if ($("statTotal")) $("statTotal").textContent = total.toString();
  if ($("statSafe")) $("statSafe").textContent = safe.toString();
  if ($("statSuspicious")) $("statSuspicious").textContent = suspicious.toString();
  if ($("statPhishing")) $("statPhishing").textContent = phishing.toString();

  renderDonutChart(safe, suspicious, phishing);
  renderBarChart(currentHistory);
  filterHistory();
}

// 9. Real-Time Storage Observer (Requirement 7)
chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local") {
    console.log("[SafeSurf Pro:Dash] Live storage change detected:", Object.keys(changes));
    let hasChanged = false;

    if (changes.theme_preference) {
      if (changes.theme_preference.newValue === "dark") {
        document.body.classList.remove("light-theme");
        document.body.classList.add("dark-theme");
      } else if (changes.theme_preference.newValue === "light") {
        document.body.classList.remove("dark-theme");
        document.body.classList.add("light-theme");
      }
    }

    if (changes.blocking_enabled && $("dashBlockingToggle")) {
      $("dashBlockingToggle").checked = !!changes.blocking_enabled.newValue;
    }

    if (changes.scan_history) {
      currentHistory = Array.isArray(changes.scan_history.newValue) ? changes.scan_history.newValue : [];
      hasChanged = true;
    }
    if (changes.threat_stats) {
      currentStats = changes.threat_stats.newValue || HistoryManager.recalculateThreatStats(currentHistory);
      hasChanged = true;
    } else if (changes.scan_history) {
      currentStats = HistoryManager.recalculateThreatStats(currentHistory);
      hasChanged = true;
    }

    if (hasChanged) {
      updateUI();
    }
  }
});

// 10. Initial Load
async function loadDashboard() {
  try {
    await initTheme();
  } catch (e) {
    console.debug("[SafeSurf Pro:Dash] initTheme error:", e);
  }

  try {
    await initSettings();
  } catch (e) {
    console.debug("[SafeSurf Pro:Dash] initSettings error:", e);
  }

  try {
    currentHistory = await HistoryManager.getHistory();
    currentStats = await HistoryManager.getStats();
  } catch (e) {
    console.error("[SafeSurf Pro:Dash] Failed to load history or stats:", e);
    currentHistory = [];
    currentStats = { totalScans: 0, safeCount: 0, suspiciousCount: 0, phishingCount: 0 };
  }

  console.log(`[SafeSurf Pro:Dash] Loaded ${currentHistory.length} scan records. Total stats:`, currentStats);
  updateUI();

  $("searchInput")?.addEventListener("input", filterHistory);
  $("riskFilter")?.addEventListener("change", filterHistory);
  $("exportCsvBtn")?.addEventListener("click", exportToCsv);
  $("clearHistoryBtn")?.addEventListener("click", clearHistory);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", loadDashboard);
} else {
  loadDashboard();
}
