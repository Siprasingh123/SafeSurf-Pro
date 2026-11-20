/**
 * SafeSurf Pro - Advanced In-Page Content Security & Threat Analyzer
 * Inspects fake login forms, credential harvesting, suspicious redirects,
 * external form actions, phishing trigger phrases, and renders passive real-time alerts.
 * Supports SPA navigations (pushState, popstate) and on-demand background scanning.
 */

(() => {
  // Only execute on valid HTTP/HTTPS top-level documents
  if (!location.protocol || !/^https?:/i.test(location.protocol)) {
    return;
  }
  if (window.top !== window) {
    return;
  }

  let lastScannedUrl = "";
  let isScanning = false;

  function inspectDomAndCollectFindings() {
    const host = location.hostname.toLowerCase();
    const findings = [];
    const meta = {
      password_field_present: 0,
      external_form_action: 0,
      insecure_form_action: 0,
      phishing_keyword_count: 0,
      fake_login_detected: 0,
      suspicious_redirect_detected: 0,
      hidden_iframe_detected: 0,
      mixed_content_detected: 0
    };

    // 1. Password & Credential Input Inspection
    const passwordInputs = Array.from(document.querySelectorAll("input[type=password]"));
    if (passwordInputs.length > 0) {
      meta.password_field_present = 1;
      if (location.protocol === "http:") {
        findings.push({
          sev: "high",
          cat: "credentials",
          msg: "Critical: Password field found on an unencrypted (HTTP) page. Credentials can be intercepted in transit."
        });
      }
    }

    // Detect sensitive credential harvesting inputs (Card, CVV, SSN, Seed Phrase)
    const sensitiveSelectors = [
      'input[name*="cvv" i]', 'input[name*="cvc" i]', 'input[name*="card" i]',
      'input[name*="ssn" i]', 'input[name*="pin" i]', 'textarea[name*="seed" i]',
      'input[name*="seed" i]', 'textarea[name*="mnemonic" i]'
    ];
    try {
      const sensitiveInputs = document.querySelectorAll(sensitiveSelectors.join(","));
      if (sensitiveInputs.length > 0) {
        findings.push({
          sev: "high",
          cat: "credentials",
          msg: "Sensitive data collection detected: Page requests payment card, PIN, SSN, or crypto seed phrase information."
        });
      }
    } catch {}

    // 2. External Form Actions Inspection
    const seenForms = new Set();
    document.querySelectorAll("form").forEach((form) => {
      const rawAction = form.getAttribute("action");
      const hasPassword = form.querySelector("input[type=password]") !== null;

      if (!rawAction || rawAction.trim() === "" || rawAction === "#") {
        if (hasPassword) {
          findings.push({
            sev: "med",
            cat: "form",
            msg: "Form with password has empty action (submits to self or uses dynamic JavaScript interception)."
          });
        }
        return;
      }

      try {
        const targetUrl = new URL(rawAction, location.href);
        const targetHost = targetUrl.hostname.toLowerCase();

        if (targetUrl.protocol.startsWith("http") && targetHost !== host && !seenForms.has(targetHost)) {
          seenForms.add(targetHost);
          meta.external_form_action = 1;
          findings.push({
            sev: "high",
            cat: "form",
            msg: `External form transmission: Form sends user input to an external host (${targetHost}).`
          });
        }

        if (location.protocol === "https:" && targetUrl.protocol === "http:") {
          meta.insecure_form_action = 1;
          findings.push({
            sev: "high",
            cat: "mixed_content",
            msg: "Insecure form action: HTTPS page submits user form input over unencrypted HTTP protocol."
          });
        }

        if (targetUrl.protocol === "data:" || targetUrl.protocol === "javascript:") {
          findings.push({
            sev: "high",
            cat: "form",
            msg: `Suspicious form action protocol (${targetUrl.protocol}) detected.`
          });
        }
      } catch {}
    });

    // 3. Fake Login Overlays / Deceptive Modal Detection
    try {
      const suspiciousModals = document.querySelectorAll(
        'div[style*="z-index"][style*="fixed"], div[style*="z-index"][style*="absolute"], dialog[open], .login-modal, .signin-overlay'
      );
      suspiciousModals.forEach((modal) => {
        if (modal.querySelector("input[type=password]")) {
          const rect = modal.getBoundingClientRect();
          if (rect.width > 280 && rect.height > 200) {
            meta.fake_login_detected = 1;
            findings.push({
              sev: "med",
              cat: "form",
              msg: "Floating or overlay login dialog detected. Verify this is not a spoofed credential harvesting prompt."
            });
          }
        }
      });
    } catch {}

    // 4. Suspicious Redirect Inspection (Meta Refresh & JS Redirects)
    const metaRefresh = document.querySelector('meta[http-equiv="refresh" i]');
    if (metaRefresh) {
      const contentAttr = metaRefresh.getAttribute("content") || "";
      const match = contentAttr.match(/url\s*=\s*['"]?([^'"]+)['"]?/i);
      if (match) {
        try {
          const dest = new URL(match[1], location.href);
          if (dest.hostname !== host) {
            meta.suspicious_redirect_detected = 1;
            findings.push({
              sev: "high",
              cat: "redirect",
              msg: `Automatic meta-refresh redirecting browser to external domain (${dest.hostname}).`
            });
          }
        } catch {}
      }
    }

    // 5. Extended Brand Typosquatting & Impersonation Heuristics
    const brands = {
      google: ["google.com", "google.co.in", "youtube.com"],
      facebook: ["facebook.com", "fb.com", "meta.com"],
      amazon: ["amazon.com", "amazon.in"],
      paypal: ["paypal.com"],
      microsoft: ["microsoft.com", "live.com", "office.com"],
      apple: ["apple.com", "icloud.com"],
      netflix: ["netflix.com"],
      chase: ["chase.com"],
      bankofamerica: ["bankofamerica.com"],
      wellsfargo: ["wellsfargo.com"],
      sbi: ["sbi.co.in", "onlinesbi.sbi"],
      hdfcbank: ["hdfcbank.com"],
      icicibank: ["icicibank.com"],
      flipkart: ["flipkart.com"],
      binance: ["binance.com"],
      metamask: ["metamask.io"]
    };

    const isOfficial = (ds) => ds.some((d) => host === d || host.endsWith("." + d));
    const lev = (a, b) => {
      const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
      for (let j = 1; j <= b.length; j++) d[0][j] = j;
      for (let i = 1; i <= a.length; i++)
        for (let j = 1; j <= b.length; j++)
          d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
      return d[a.length][b.length];
    };

    const labels = host.replace(/^www\./, "").split(".");
    const name = labels.length > 1 ? labels[labels.length - 2] : labels[0];
    const parts = name.split(/[-_]/);

    for (const [brand, official] of Object.entries(brands)) {
      if (isOfficial(official) || host === "localhost" || host.includes("127.0.0.1")) continue;
      const typo = parts.some((p) => p !== brand && lev(p, brand) <= (brand.length > 4 ? 2 : 1));
      const contains = brand.length >= 4 && host.includes(brand);
      if (typo) {
        findings.push({ sev: "high", cat: "brand", msg: `"${host}" looks like a typosquatted fake copy of ${brand}.` });
        break;
      }
      if (contains) {
        findings.push({ sev: "high", cat: "brand", msg: `"${host}" unauthorizedly uses the brand name "${brand}".` });
        break;
      }
    }

    // 6. Punycode Domain Check
    if (host.includes("xn--")) {
      findings.push({
        sev: "high",
        cat: "domain",
        msg: "Punycode (IDN) domain detected: Often utilized in homoglyph spoofing attacks."
      });
    }

    // 7. Comprehensive Phishing Trigger Words & High Urgency Phrases
    const pageText = (document.body?.innerText || "").toLowerCase().slice(0, 30000);
    const urgentPhrases = [
      "verify your account", "account suspended", "account has been locked",
      "confirm your identity", "unusual activity", "update your payment",
      "your account will be closed", "act now", "verify now", "unauthorized login",
      "security alert", "tax refund", "urgent payment", "wire transfer",
      "crypto giveaway", "wallet connection", "seed phrase", "secret recovery phrase",
      "enter your 2fa", "otp verification", "session expired", "kyc verification"
    ];

    const matchedPhrases = urgentPhrases.filter((w) => pageText.includes(w));
    meta.phishing_keyword_count = matchedPhrases.length;

    if (matchedPhrases.length > 0 && passwordInputs.length > 0) {
      findings.push({
        sev: "high",
        cat: "phishing_keywords",
        msg: `Urgent phishing keywords paired with credential form: "${matchedPhrases.slice(0, 2).join('", "')}".`
      });
    } else if (matchedPhrases.length >= 3) {
      findings.push({
        sev: "med",
        cat: "phishing_keywords",
        msg: `Multiple high-urgency psychological manipulation phrases detected: "${matchedPhrases.slice(0, 3).join('", "')}".`
      });
    }

    // 8. Third-Party Scripts Count
    const thirdParty = [...new Set(
      [...document.scripts].map((s) => s.src).filter(Boolean)
        .map((u) => { try { return new URL(u).hostname; } catch { return ""; } })
        .filter((h) => h && h !== host)
    )];
    if (thirdParty.length > 12) {
      findings.push({
        sev: "med",
        cat: "scripts",
        msg: `High volume of external scripts (${thirdParty.length} external third-party script sources).`
      });
    }

    // 9. Hidden / Zero-Pixel iFrame Inspection (Drive-by / Clickjacking / Hijack vectors)
    try {
      const iframes = document.querySelectorAll("iframe");
      let hiddenExternalCount = 0;
      iframes.forEach((frame) => {
        const src = frame.getAttribute("src") || "";
        if (!src || src.startsWith("about:") || src.startsWith("javascript:")) return;
        try {
          const frameUrl = new URL(src, location.href);
          if (frameUrl.hostname && frameUrl.hostname !== host) {
            const width = frame.offsetWidth || parseInt(frame.width || "0", 10);
            const height = frame.offsetHeight || parseInt(frame.height || "0", 10);
            const style = window.getComputedStyle ? window.getComputedStyle(frame) : {};
            const isHidden = (width <= 1 && height <= 1) ||
                            style.display === "none" ||
                            style.visibility === "hidden" ||
                            style.opacity === "0";
            if (isHidden) {
              hiddenExternalCount++;
            }
          }
        } catch {}
      });

      if (hiddenExternalCount > 0) {
        meta.hidden_iframe_detected = 1;
        findings.push({
          sev: "high",
          cat: "iframe",
          msg: `Deceptive hidden iframe detected (${hiddenExternalCount} hidden external frame(s) communicating with third-party domain).`
        });
      }
    } catch {}

    // 10. Mixed Active Content Inspection (Insecure scripts loaded on HTTPS)
    if (location.protocol === "https:") {
      const insecureScripts = Array.from(document.querySelectorAll("script[src^='http://']"));
      if (insecureScripts.length > 0) {
        meta.mixed_content_detected = 1;
        findings.push({
          sev: "high",
          cat: "mixed_content",
          msg: `Mixed active content: Page loads ${insecureScripts.length} executable script(s) over unencrypted HTTP.`
        });
      }
    }

    return { findings, thirdParty, meta };
  }

  function executeAndSendScan(force = false) {
    const currentUrl = location.href;
    if (!currentUrl || !currentUrl.startsWith("http")) return null;
    if (!force && currentUrl === lastScannedUrl) {
      return null;
    }
    if (isScanning && !force) return null;

    isScanning = true;
    lastScannedUrl = currentUrl; // Immediately update to prevent concurrent duplicate sends

    const data = inspectDomAndCollectFindings();
    const payload = {
      type: "scan",
      url: currentUrl,
      findings: data.findings,
      thirdParty: data.thirdParty,
      meta: data.meta
    };

    try {
      if (chrome.runtime?.id) {
        chrome.runtime.sendMessage(payload, (response) => {
          isScanning = false;
          if (chrome.runtime.lastError) {
            console.debug("[SafeSurf Pro:CS] Background worker response error:", chrome.runtime.lastError.message);
          } else {
            console.log("[SafeSurf Pro:CS] Scan transmitted successfully for:", currentUrl);
          }
        });
      } else {
        isScanning = false;
      }
    } catch (e) {
      isScanning = false;
      console.debug("[SafeSurf Pro:CS] Context invalidation or dispatch error:", e);
    }

    return payload;
  }

  // Initial scan on load (guarded to schedule exactly once)
  let initialScanScheduled = false;
  function scheduleInitialScan() {
    if (initialScanScheduled) return;
    initialScanScheduled = true;
    setTimeout(() => executeAndSendScan(false), 200);
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    scheduleInitialScan();
  } else {
    window.addEventListener("DOMContentLoaded", scheduleInitialScan, { once: true });
    window.addEventListener("load", scheduleInitialScan, { once: true });
  }

  // Single Page Application (SPA) navigation listeners
  window.addEventListener("popstate", () => setTimeout(() => executeAndSendScan(false), 300));
  window.addEventListener("hashchange", () => setTimeout(() => executeAndSendScan(false), 300));

  const origPush = history.pushState;
  if (origPush) {
    history.pushState = function(...args) {
      const res = origPush.apply(this, args);
      setTimeout(() => executeAndSendScan(false), 300);
      return res;
    };
  }

  const origReplace = history.replaceState;
  if (origReplace) {
    history.replaceState = function(...args) {
      const res = origReplace.apply(this, args);
      setTimeout(() => executeAndSendScan(false), 300);
      return res;
    };
  }

  // Handle messages from background worker
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type === "REQUEST_PAGE_SCAN") {
      const data = inspectDomAndCollectFindings();
      lastScannedUrl = location.href;
      sendResponse({
        status: "scanned",
        data: {
          url: location.href,
          findings: data.findings,
          thirdParty: data.thirdParty,
          meta: data.meta
        }
      });
      return true;
    }
    if (msg?.type === "SHOW_PASSIVE_ALERT" && !document.getElementById("safesurf-alert-banner")) {
      renderPassiveAlertBanner(msg.riskTier, msg.reasons || []);
      sendResponse({ status: "alert_rendered" });
      return true;
    }
  });

  // Safe DOM manipulation for passive warning banner
  function renderPassiveAlertBanner(riskTier, reasons) {
    const banner = document.createElement("div");
    banner.id = "safesurf-alert-banner";
    const isMedium = riskTier === "Medium";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background: ${isMedium ? "#b45309" : "#7f1d1d"};
      color: #ffffff;
      padding: 12px 18px;
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-sizing: border-box;
      font-size: 13px;
    `;

    const left = document.createElement("div");
    left.style.display = "flex";
    left.style.alignItems = "center";
    left.style.gap = "10px";

    const icon = document.createElement("span");
    icon.textContent = "\uD83D\uDEA8";
    icon.style.fontSize = "18px";
    left.appendChild(icon);

    const textDiv = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `SafeSurf Pro Alert: ${riskTier} Phishing Risk Detected!`;
    title.style.display = "block";
    title.style.fontSize = "14px";
    textDiv.appendChild(title);

    if (reasons.length > 0) {
      const sub = document.createElement("span");
      sub.textContent = reasons[0];
      sub.style.opacity = "0.9";
      textDiv.appendChild(sub);
    }
    left.appendChild(textDiv);
    banner.appendChild(left);

    const closeBtn = document.createElement("button");
    closeBtn.textContent = "\u2715 Dismiss";
    closeBtn.style.cssText = `
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.4);
      color: white;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      font-weight: 500;
    `;
    closeBtn.addEventListener("click", () => banner.remove());
    banner.appendChild(closeBtn);

    document.documentElement.prepend(banner);
  }
})();
