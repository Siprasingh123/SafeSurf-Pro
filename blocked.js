/**
 * SafeSurf Pro - Interstitial Warning Page Script
 * Safely parses target parameters, displays AI risk factors,
 * and allows user to navigate back or proceed at their own risk.
 */

(() => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown site";
  const score = params.get("score") || "High";
  const reason = params.get("reason") || "Suspicious phishing patterns detected.";

  // Safe DOM text assignments (prevent XSS)
  document.getElementById("targetUrl").textContent = targetUrl;
  document.getElementById("riskScore").textContent = `${score}/100`;
  document.getElementById("primaryReason").textContent = reason;

  document.getElementById("goBackBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "about:blank";
    }
  });

  document.getElementById("proceedBtn").addEventListener("click", () => {
    if (targetUrl && /^https?:/i.test(targetUrl)) {
      if (chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({ type: "ALLOW_BYPASS", url: targetUrl }, () => {
          window.location.href = targetUrl;
        });
      } else {
        window.location.href = targetUrl;
      }
    } else {
      alert("Invalid target URL.");
    }
  });
})();
