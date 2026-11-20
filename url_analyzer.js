/**
 * SafeSurf Pro - Advanced URL & Domain Security Analyzer
 * Analyzes URL length, entropy, IP hosts, suspicious characters, subdomains,
 * HTTPS, brand impersonation, typosquatting, Punycode, and Unicode homoglyphs.
 */

const URLAnalyzer = (() => {
  const SUSPICIOUS_TLDS = new Set([
    "top", "xyz", "click", "loan", "work", "fit", "country", "zip", "tk",
    "ml", "ga", "cf", "gq", "gdn", "racing", "download", "stream", "review",
    "trade", "party", "date", "faith", "accountant", "bid", "cricket", "science"
  ]);

  // Extended official brand registry
  const BRANDS = {
    google: ["google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "youtube.com", "gmail.com"],
    facebook: ["facebook.com", "fb.com", "meta.com"],
    amazon: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "aws.amazon.com"],
    paypal: ["paypal.com", "paypal.me"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com", "bing.com", "azure.com"],
    apple: ["apple.com", "icloud.com"],
    netflix: ["netflix.com"],
    chase: ["chase.com"],
    bankofamerica: ["bankofamerica.com", "bofa.com"],
    wellsfargo: ["wellsfargo.com"],
    sbi: ["sbi.co.in", "onlinesbi.sbi"],
    hdfcbank: ["hdfcbank.com"],
    icicibank: ["icicibank.com"],
    flipkart: ["flipkart.com"],
    steam: ["steampowered.com", "steamcommunity.com"],
    yahoo: ["yahoo.com"],
    twitter: ["twitter.com", "x.com"],
    instagram: ["instagram.com"],
    linkedin: ["linkedin.com"],
    dropbox: ["dropbox.com"],
    binance: ["binance.com"],
    coinbase: ["coinbase.com"],
    metamask: ["metamask.io"],
    whatsapp: ["whatsapp.com"],
    telegram: ["telegram.org", "t.me"]
  };

  // Cyrillic & Greek homoglyph mapping to Latin
  const HOMOGLYPHS = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0455": "s", "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j",
    "\u03B1": "a", "\u03BF": "o", "\u03C1": "p", "\u03BD": "v"
  };

  function normalizeHomoglyphs(str) {
    let out = "";
    for (const ch of str) {
      out += HOMOGLYPHS[ch] || ch;
    }
    return out;
  }

  function shannonEntropy(text) {
    if (!text || text.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    let entropy = 0;
    const len = text.length;
    for (const c in freq) {
      const p = freq[c] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 10000) / 10000;
  }

  function isIpHost(host) {
    if (!host) return false;
    const clean = host.split(":")[0];
    // IPv4 pattern
    const ipv4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    if (ipv4.test(clean)) return true;
    // IPv6
    if (clean.includes(":") && /^[0-9a-fA-F:]+$/.test(clean)) return true;
    // Hex / Octal representations (e.g. 0x7f000001 or pure integer)
    if (/^0x[0-9a-fA-F]+$/i.test(clean) || (/^\d+$/.test(clean) && clean.length >= 8)) return true;
    return false;
  }

  function levenshtein(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
      }
    }
    return d[a.length][b.length];
  }

  function isOfficialBrandHost(host, officialDomains) {
    return officialDomains.some(d => host === d || host.endsWith("." + d));
  }

  function analyzeBrandImpersonation(hostname) {
    const host = hostname.toLowerCase().replace(/^www\./, "");
    const reasons = [];
    let maxSimilarity = 0.0;
    let spoofedBrand = null;

    // Check if host contains decoded Punycode or homoglyphs
    const normalized = normalizeHomoglyphs(host);
    const hasHomoglyphs = normalized !== host;

    const parts = host.split(".");
    const domainBody = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    const subparts = domainBody.split(/[-_]/);

    for (const [brand, officialList] of Object.entries(BRANDS)) {
      if (isOfficialBrandHost(host, officialList) || host === "localhost") {
        continue;
      }

      // Check homoglyph attack
      if (hasHomoglyphs && normalizeHomoglyphs(domainBody).includes(brand)) {
        reasons.push(`Internationalized homoglyph disguise detected: domain mimics "${brand}" using lookalike characters.`);
        maxSimilarity = Math.max(maxSimilarity, 0.95);
        spoofedBrand = brand;
      }

      // Check if official domain name is placed in subdomain (subdomain spoofing)
      // e.g. "paypal.com.login-portal.net"
      for (const off of officialList) {
        if (host.includes(off) && !host.endsWith("." + off) && host !== off) {
          reasons.push(`Domain spoofing: brand name "${off}" placed inside subdomains of an unrelated host.`);
          maxSimilarity = Math.max(maxSimilarity, 0.92);
          spoofedBrand = brand;
          break;
        }
      }

      // Check typosquatting on domain subparts
      for (const part of subparts) {
        if (!part) continue;
        const normPart = normalizeHomoglyphs(part);
        const dist = levenshtein(normPart, brand);
        const threshold = brand.length > 5 ? 2 : 1;

        if (part !== brand && dist <= threshold) {
          const sim = 1.0 - (dist / Math.max(part.length, brand.length));
          maxSimilarity = Math.max(maxSimilarity, Math.round(sim * 100) / 100);
          reasons.push(`Typosquatting detected: "${part}" is suspiciously close to "${brand}" (edit distance ${dist}).`);
          spoofedBrand = brand;
        } else if (brand.length >= 4 && part.includes(brand)) {
          reasons.push(`Brand keyword misuse: "${host}" embeds brand name "${brand}" without being their official domain.`);
          maxSimilarity = Math.max(maxSimilarity, 0.85);
          spoofedBrand = brand;
        }
      }
    }

    return {
      brandSimilarityScore: maxSimilarity,
      spoofedBrand,
      reasons
    };
  }

  function analyze(urlStr) {
    let url;
    try {
      url = new URL(urlStr);
    } catch {
      return null;
    }

    const host = (url.hostname || "").toLowerCase();
    const cleanHost = host.replace(/^www\./, "");
    const path = url.pathname || "";
    const protocol = (url.protocol || "").toLowerCase();

    const hostParts = cleanHost.split(".");
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : "";
    const isSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);
    const isIp = isIpHost(cleanHost);
    const isPunycode = cleanHost.includes("xn--");
    const subdomainCount = isIp ? 0 : Math.max(0, hostParts.length - 2);

    const urlEntropy = shannonEntropy(urlStr);
    const hostEntropy = shannonEntropy(cleanHost);

    const hyphensHost = (cleanHost.match(/-/g) || []).length;
    const dotsUrl = (urlStr.match(/\./g) || []).length;
    const digitsHost = (cleanHost.match(/\d/g) || []).length;
    const suspiciousChars = (urlStr.match(/[@_%~!$*=]/g) || []).length;
    const hasAt = urlStr.includes("@");
    const hasDoubleSlashPath = path.includes("//");
    const isHttps = protocol === "https:";
    const hasNonStandardPort = !!(url.port && url.port !== "80" && url.port !== "443");

    const brandAnalysis = analyzeBrandImpersonation(cleanHost);

    // Collect explainable reasons for URL analysis
    const reasons = [...brandAnalysis.reasons];
    if (isIp) {
      reasons.push(`Direct IP address used instead of a registered domain name (${cleanHost}).`);
    }
    if (isPunycode) {
      reasons.push(`Punycode domain (${cleanHost}): often used in homograph attacks to impersonate legitimate websites.`);
    }
    if (isSuspiciousTLD) {
      reasons.push(`High-risk Top-Level Domain (.${tld}): frequently associated with disposable phishing campaigns.`);
    }
    if (hasAt) {
      reasons.push(`"@" symbol in URL: classic browser credential spoofing indicator.`);
    }
    if (hasDoubleSlashPath) {
      reasons.push(`Path contains "//": suspicious redirect evasion technique.`);
    }
    if (subdomainCount >= 3) {
      reasons.push(`Excessive subdomain depth (${subdomainCount} subdomains): used to camouflage malicious hosts.`);
    }
    if (hyphensHost >= 3) {
      reasons.push(`Multiple hyphens in domain (${hyphensHost}): common pattern in credential harvesting setups.`);
    }
    if (hostEntropy >= 4.2) {
      reasons.push(`Abnormally high domain randomness/entropy (${hostEntropy}): characteristic of domain generation algorithms (DGA).`);
    }
    if (hasNonStandardPort) {
      reasons.push(`Non-standard web port (:${url.port}): uncommon for reputable public services.`);
    }
    if (!isHttps) {
      reasons.push(`Unencrypted connection (HTTP): credentials and data can be intercepted.`);
    }

    // Construct feature vector for ML (20 features)
    const features = [
      urlStr.length,
      cleanHost.length,
      urlEntropy,
      hostEntropy,
      isIp ? 1 : 0,
      subdomainCount,
      hyphensHost,
      dotsUrl,
      digitsHost,
      isSuspiciousTLD ? 1 : 0,
      suspiciousChars,
      hasAt ? 1 : 0,
      hasDoubleSlashPath ? 1 : 0,
      isPunycode ? 1 : 0,
      brandAnalysis.brandSimilarityScore,
      hasNonStandardPort ? 1 : 0,
      isHttps ? 1 : 0,
      0, // placeholder: external_form_action
      0, // placeholder: password_field_present
      0  // placeholder: phishing_keyword_count
    ];

    return {
      url: urlStr,
      host: cleanHost,
      protocol,
      isHttps,
      isIp,
      isPunycode,
      isSuspiciousTLD,
      tld,
      subdomainCount,
      urlEntropy,
      hostEntropy,
      hasNonStandardPort,
      brandAnalysis,
      reasons,
      features
    };
  }

  return {
    analyze,
    shannonEntropy,
    isIpHost,
    levenshtein,
    normalizeHomoglyphs,
    BRANDS,
    SUSPICIOUS_TLDS
  };
})();

if (typeof globalThis !== "undefined") globalThis.URLAnalyzer = URLAnalyzer;
if (typeof self !== "undefined") self.URLAnalyzer = URLAnalyzer;
if (typeof module !== "undefined" && module.exports) {
  module.exports = URLAnalyzer;
}
