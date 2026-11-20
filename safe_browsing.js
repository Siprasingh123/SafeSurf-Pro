/**
 * SafeSurf Pro - Google Safe Browsing API v4 Integration
 * Performs threat intelligence lookups against Google Safe Browsing database.
 * Preserves user privacy and security: API keys are configured by the user,
 * stored in chrome.storage.local, and never hardcoded in frontend code.
 */

const SafeBrowsing = (() => {
  const API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find";

  async function getApiKey() {
    try {
      const data = await chrome.storage.local.get("safe_browsing_api_key");
      return data.safe_browsing_api_key || "";
    } catch {
      return "";
    }
  }

  async function checkUrl(urlToCheck) {
    const apiKey = await getApiKey();

    if (!apiKey) {
      return {
        configured: false,
        flagged: false,
        threatTypes: [],
        statusText: "Google Safe Browsing: Not configured (Local AI & Heuristic Intelligence active)"
      };
    }

    try {
      const payload = {
        client: {
          clientId: "safesurf-pro",
          clientVersion: "2.1.0"
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: urlToCheck }]
        }
      };

      const res = await fetch(`${API_ENDPOINT}?key=${encodeURIComponent(apiKey)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        return {
          configured: true,
          flagged: false,
          threatTypes: [],
          statusText: `Safe Browsing API response: HTTP ${res.status}`
        };
      }

      const result = await res.json();
      const matches = result.matches || [];

      if (matches.length > 0) {
        const threatTypes = [...new Set(matches.map(m => m.threatType))];
        return {
          configured: true,
          flagged: true,
          threatTypes,
          statusText: `Flagged by Google Safe Browsing: ${threatTypes.join(", ")}`
        };
      }

      return {
        configured: true,
        flagged: false,
        threatTypes: [],
        statusText: "Verified Safe by Google Safe Browsing"
      };
    } catch (err) {
      return {
        configured: true,
        flagged: false,
        threatTypes: [],
        statusText: `Safe Browsing check failed (offline or network error)`
      };
    }
  }

  return {
    checkUrl,
    getApiKey
  };
})();

if (typeof globalThis !== "undefined") globalThis.SafeBrowsing = SafeBrowsing;
if (typeof self !== "undefined") self.SafeBrowsing = SafeBrowsing;
if (typeof module !== "undefined" && module.exports) {
  module.exports = SafeBrowsing;
}
