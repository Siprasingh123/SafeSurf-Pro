/**
 * SafeSurf Pro - Extension Popup Script
 * Manages Dual Scores (Security & Phishing), Explainable AI breakdown,
 * security headers inspection, theme preferences, and dashboard navigation.
 * Dynamically reacts to live scans via chrome.storage.onChanged.
 */

const $ = (id) => document.getElementById(id);

// Safe DOM element helper
function createElementWithText(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined && text !== null) el.textContent = text;
  if (className) el.className = className;
  return el;
}

// System / User theme initialization
async function initTheme() {
  const store = await chrome.storage.local.get("theme_preference");
  const pref = store.theme_preference;
  if (pref === "dark") {
    document.body.classList.add("dark-theme");
  } else if (pref === "light") {
    document.body.classList.add("light-theme");
  }

  $("themeToggle").addEventListener("click", async () => {
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

// Active Blocking toggle
async function initBlockingToggle() {
  const store = await chrome.storage.local.get("blocking_enabled");
  const toggle = $("blockingToggle");
  toggle.checked = !!store.blocking_enabled;

  toggle.addEventListener("change", async () => {
    await chrome.storage.local.set({ blocking_enabled: toggle.checked });
  });
}

// Dashboard opener
$("openDashboardBtn").addEventListener("click", () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
});

function renderScanData(tab, url, h, s) {
  $("site").textContent = url.hostname;

  const secScore = s?.securityScore !== undefined ? s.securityScore : (url.protocol === "https:" ? 75 : 40);
  const phishScore = s?.phishingRiskScore !== undefined ? s.phishingRiskScore : 0;
  const riskTier = s?.riskTier || (phishScore >= 75 ? "Critical" : phishScore >= 50 ? "High" : phishScore >= 25 ? "Medium" : "Low");

  // Render Dual Scores
  const secEl = $("securityScore");
  secEl.textContent = `${secScore}/100`;
  secEl.className = "score-val " + (secScore >= 75 ? "good-score" : secScore >= 45 ? "mid-score" : "bad-score");

  const phishEl = $("phishingScore");
  phishEl.textContent = `${phishScore}/100`;
  phishEl.className = "score-val " + (phishScore < 30 ? "good-score" : phishScore < 65 ? "mid-score" : "bad-score");
  $("phishingSub").textContent = `Risk Level: ${riskTier}`;

  // Status Badge
  const badge = $("statusBadge");
  if (riskTier === "Critical" || riskTier === "High") {
    badge.textContent = `\uD83D\uDEA8 ${riskTier} Phishing Risk`;
    badge.className = "status-badge status-phishing";
  } else if (riskTier === "Medium") {
    badge.textContent = `\u26A0\uFE0F Suspicious Signals`;
    badge.className = "status-badge status-suspicious";
  } else {
    badge.textContent = `\u2714 Verified Safe`;
    badge.className = "status-badge status-safe";
  }

  // Populate Explainable AI Insights
  const xaiBox = $("xaiList");
  xaiBox.replaceChildren();

  const allReasons = s?.reasons || [];
  $("reasonsCount").textContent = `${allReasons.length} signal${allReasons.length === 1 ? "" : "s"}`;

  if (allReasons.length === 0) {
    const emptyRow = createElementWithText(
      "div",
      "\u2705 No malicious or suspicious signals detected on this website.",
      "reason-item"
    );
    xaiBox.appendChild(emptyRow);
  } else {
    for (const r of allReasons) {
      const row = createElementWithText("div", "", "reason-item");

      const catName = r.category || "Signal";
      const tag = createElementWithText("span", catName, "reason-tag");
      if (catName.includes("AI")) tag.classList.add("tag-ai");
      else if (catName.includes("URL")) tag.classList.add("tag-url");
      else if (catName.includes("Content")) tag.classList.add("tag-content");
      else tag.classList.add("tag-intel");

      const textSpan = createElementWithText("span", r.text || r);
      textSpan.style.flex = "1";

      row.appendChild(tag);
      row.appendChild(textSpan);
      xaiBox.appendChild(row);
    }
  }

  // Populate Security Posture Checks
  const checksList = $("checksList");
  checksList.replaceChildren();

  function addCheckRow(statusOk, name, desc) {
    const row = createElementWithText("div", "", "check-row");
    const left = createElementWithText("div", "", "check-left");
    const icon = createElementWithText("span", statusOk ? "\u2705" : "\u274C");
    const title = createElementWithText("strong", name);
    left.appendChild(icon);
    left.appendChild(title);

    const right = createElementWithText("span", desc, "check-desc");
    row.appendChild(left);
    row.appendChild(right);
    checksList.appendChild(row);
  }

  addCheckRow(url.protocol === "https:", "HTTPS Protocol", url.protocol === "https:" ? "Encrypted TLS" : "Unencrypted HTTP");
  addCheckRow(!!h?.hsts, "HSTS Protection", h?.hsts ? "Strict transport active" : "Not enforced");
  addCheckRow(!!h?.csp, "CSP Header", h?.csp ? "Script injection restricted" : "No Content Security Policy");
  addCheckRow(!!h?.xfo, "Anti-Clickjacking", h?.xfo ? "X-Frame / ancestors secure" : "Vulnerable to framing");
  addCheckRow(!!h?.nosniff, "MIME Sniffing Blocked", h?.nosniff ? "nosniff enabled" : "Missing nosniff header");
  addCheckRow(!!h?.referrer, "Referrer Policy", h?.referrer ? "Referrer data protected" : "No Referrer-Policy set");

  // Check for mixed content findings
  const mixedFinding = (s?.findings || []).find((f) => f.cat === "mixed_content");
  if (mixedFinding) {
    addCheckRow(false, "Mixed Content", mixedFinding.msg);
  }

  // Cookie checks
  chrome.cookies.getAll({ url: tab.url }, (cookies) => {
    if (chrome.runtime.lastError || !cookies) return;
    if (cookies.length > 0) {
      const weak = cookies.filter((c) => !c.secure || !c.httpOnly).length;
      addCheckRow(weak === 0, "Cookie Security", `${weak} of ${cookies.length} lack Secure/HttpOnly flags`);
    } else {
      addCheckRow(true, "Cookies", "No cookies set on this page");
    }
  });

  const thirdPartyCount = s?.thirdParty?.length || 0;
  $("foot").textContent = `External script sources: ${thirdPartyCount} \u2022 Local AI & Heuristic Protection Active`;
}

// Main inspection and UI population
chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
  await initTheme();
  await initBlockingToggle();

  let url;
  try {
    url = new URL(tab?.url || "");
  } catch {
    url = null;
  }

  if (!url || !/^https?:$/.test(url.protocol)) {
    $("site").textContent = "Restricted Internal Page";
    $("statusBadge").textContent = "Browser Protected";
    $("statusBadge").className = "status-badge status-safe";
    $("securityScore").textContent = "N/A";
    $("phishingScore").textContent = "N/A";
    $("xaiList").replaceChildren(
      createElementWithText("div", "Browser-internal pages (chrome://, Web Store) are isolated by Chrome security.", "reason-item")
    );
    $("checksList").replaceChildren();
    return;
  }

  $("site").textContent = url.hostname;

  // Retrieve session storage data
  const store = await chrome.storage.session.get(["hdr_" + tab.id, "scan_" + tab.id]);
  let h = store["hdr_" + tab.id];
  let s = store["scan_" + tab.id];

  const norm = (u) => String(u || "").trim().toLowerCase().replace(/\/$/, "");
  const currentNorm = norm(tab.url);

  // Validate cache freshness to prevent displaying stale data from a previous page
  if (s && norm(s.url) !== currentNorm) {
    s = null;
  }
  if (h) {
    try {
      if (new URL(h.url).origin !== url.origin) h = null;
    } catch {
      if (norm(h.url) !== currentNorm) h = null;
    }
  }

  if (s) {
    renderScanData(tab, url, h, s);
  } else {
    // Immediate on-demand scan request to background
    $("securityScore").textContent = "...";
    $("phishingScore").textContent = "...";
    $("xaiList").replaceChildren(
      createElementWithText("div", "AI scan in progress...", "reason-item")
    );

    chrome.runtime.sendMessage({
      type: "REQUEST_SCAN",
      tabId: tab.id,
      url: tab.url
    }, (res) => {
      if (res?.result) {
        chrome.storage.session.get("hdr_" + tab.id).then((freshStore) => {
          let freshH = freshStore["hdr_" + tab.id];
          if (freshH) {
            try {
              if (new URL(freshH.url).origin !== url.origin) freshH = null;
            } catch {
              if (norm(freshH.url) !== currentNorm) freshH = null;
            }
          }
          renderScanData(tab, url, freshH || h, res.result);
        });
      }
    });
  }

  // Observe live scan changes in storage.session and settings in storage.local
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes["scan_" + tab.id]) {
      const updatedScan = changes["scan_" + tab.id].newValue;
      if (updatedScan && norm(updatedScan.url) === currentNorm) {
        chrome.storage.session.get("hdr_" + tab.id).then((freshStore) => {
          let freshH = freshStore["hdr_" + tab.id];
          if (freshH) {
            try {
              if (new URL(freshH.url).origin !== url.origin) freshH = null;
            } catch {
              if (norm(freshH.url) !== currentNorm) freshH = null;
            }
          }
          renderScanData(tab, url, freshH || h, updatedScan);
        });
      }
    }

    if (area === "local") {
      if (changes.blocking_enabled && $("blockingToggle")) {
        $("blockingToggle").checked = !!changes.blocking_enabled.newValue;
      }
      if (changes.theme_preference) {
        if (changes.theme_preference.newValue === "dark") {
          document.body.classList.remove("light-theme");
          document.body.classList.add("dark-theme");
        } else if (changes.theme_preference.newValue === "light") {
          document.body.classList.remove("dark-theme");
          document.body.classList.add("light-theme");
        }
      }
    }
  });
});
