/**
 * SafeSurf Pro - Client-Side Machine Learning Inference Engine
 * Executes Random Forest & Decision Tree models exported from scikit-learn.
 * Provides real-time phishing probability, risk tiering, and Explainable AI (XAI) feature attribution.
 */

const MLEngine = (() => {
  let modelCache = null;

  function setModel(model) {
    modelCache = model;
  }

  async function loadModel() {
    if (modelCache) return modelCache;
    if (typeof globalThis !== "undefined" && globalThis.PHISHING_MODEL) {
      modelCache = globalThis.PHISHING_MODEL;
      return modelCache;
    }
    if (typeof self !== "undefined" && self.PHISHING_MODEL) {
      modelCache = self.PHISHING_MODEL;
      return modelCache;
    }
    try {
      if (typeof chrome !== "undefined" && chrome.runtime?.getURL) {
        const url = chrome.runtime.getURL("models/phishing_model.json");
        // In Node environment or browser
        if (typeof process !== "undefined" && process.versions?.node && typeof require !== "undefined") {
          try {
            const fs = require("fs");
            const raw = fs.readFileSync(url, "utf8");
            modelCache = JSON.parse(raw);
            return modelCache;
          } catch {}
        }
        const res = await fetch(url);
        modelCache = await res.json();
        return modelCache;
      }
    } catch (e) {
      console.warn("[SafeSurf Pro] Could not load JSON model file, falling back to embedded ensemble rules:", e);
    }
    return null;
  }

  function evaluateTree(node, features, contributions) {
    if (node.type === "leaf") {
      return node.probability;
    }

    const featIdx = node.feature_index;
    const featName = node.feature_name || `feature_${featIdx}`;
    const featVal = features[featIdx];

    if (featVal <= node.threshold) {
      const prob = evaluateTree(node.left, features, contributions);
      if (prob >= 0.5) {
        contributions[featName] = (contributions[featName] || 0) + 1;
      }
      return prob;
    } else {
      const prob = evaluateTree(node.right, features, contributions);
      if (prob >= 0.5) {
        contributions[featName] = (contributions[featName] || 0) + 1;
      }
      return prob;
    }
  }

  // Fallback heuristic scoring if model JSON is unreadable
  function evaluateFallback(features, contributions = {}) {
    let score = 0;
    if (features[0] > 75) { score += 15; contributions["url_length"] = 1; }
    if (features[3] > 3.8) { score += 20; contributions["host_entropy"] = 1; }
    if (features[4] === 1) { score += 35; contributions["is_ip_address"] = 1; }
    if (features[9] === 1) { score += 25; contributions["suspicious_tld"] = 1; }
    if (features[13] === 1) { score += 30; contributions["is_punycode"] = 1; }
    if (features[14] > 0.6) { score += 40; contributions["brand_similarity_score"] = 1; }
    if (features[16] === 0) { score += 15; contributions["is_https"] = 1; }
    if (features[17] === 1) { score += 35; contributions["external_form_action"] = 1; }
    if (features[18] === 1) { score += 15; contributions["password_field_present"] = 1; }
    if (features[19] > 0) { score += Math.min(features[19] * 12, 36); contributions["phishing_keyword_count"] = 1; }

    const prob = Math.min(100, score) / 100;
    return prob;
  }

  async function predict(features, featureNames = []) {
    const model = await loadModel();
    const contributions = {};
    let phishProb = 0.0;

    if (model && model.trees && model.trees.length > 0) {
      let totalProb = 0;
      for (const tree of model.trees) {
        totalProb += evaluateTree(tree, features, contributions);
      }
      phishProb = totalProb / model.trees.length;
    } else {
      phishProb = evaluateFallback(features, contributions);
      contributions["fallback_heuristic_rules"] = 1;
    }

    // Convert to percentage (0 - 100)
    const riskScore = Math.min(100, Math.max(0, Math.round(phishProb * 100)));

    let riskTier = "Low";
    if (riskScore >= 75) {
      riskTier = "Critical";
    } else if (riskScore >= 50) {
      riskTier = "High";
    } else if (riskScore >= 25) {
      riskTier = "Medium";
    }

    // Generate Explainable AI explanations based on high contributing features
    const explanations = [];
    const sortedFeatures = Object.entries(contributions).sort((a, b) => b[1] - a[1]);

    const featureDescriptions = {
      phishing_keyword_count: "Multiple high-urgency phishing trigger phrases detected in page content.",
      password_field_present: "Credential input collected on an untrusted or newly registered domain.",
      external_form_action: "Form transmits sensitive user inputs directly to an external third-party domain.",
      suspicious_tld: "Registered under a known high-abuse, low-reputation top-level domain.",
      brand_similarity_score: "Host structure strongly mimics a high-value protected brand name.",
      hyphen_count_host: "Unusually high number of hyphens used in the domain name.",
      digit_count_host: "Abnormal count of digits embedded inside the domain name.",
      host_entropy: "High character randomness (entropy) indicates algorithmic generation.",
      is_ip_address: "Direct numerical IP access bypassing standard DNS safety controls.",
      is_punycode: "Punycode internationalized domain used to mislead users with lookalike characters.",
      is_https: "Insecure transmission protocol without SSL/TLS encryption.",
      url_length: "Excessive URL length commonly utilized in credential phishing links."
    };

    for (const [feat, weight] of sortedFeatures) {
      if (featureDescriptions[feat]) {
        explanations.push(featureDescriptions[feat]);
      }
    }

    return {
      riskScore,
      probability: Math.round(phishProb * 1000) / 1000,
      riskTier,
      isPhishing: riskScore >= 50,
      explanations,
      featureContributions: contributions
    };
  }

  return {
    loadModel,
    setModel,
    predict,
    evaluateFallback
  };
})();

if (typeof globalThis !== "undefined") globalThis.MLEngine = MLEngine;
if (typeof self !== "undefined") self.MLEngine = MLEngine;
if (typeof module !== "undefined" && module.exports) {
  module.exports = MLEngine;
}
