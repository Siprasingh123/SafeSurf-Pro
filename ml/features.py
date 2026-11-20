"""
SafeSurf Pro - ML Feature Extraction Engine
Extracts numerical and categorical security features from URLs and webpage metadata.
"""

import math
import re
from urllib.parse import urlparse

# Suspicious TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "loan", "work", "fit", "country", "zip", "tk",
    "ml", "ga", "cf", "gq", "gdn", "racing", "download", "stream", "review",
    "trade", "party", "date", "faith", "accountant", "bid", "cricket", "science"
}

# High-profile targeted brands
MAJOR_BRANDS = [
    "google", "facebook", "amazon", "paypal", "microsoft", "apple", "netflix",
    "chase", "bankofamerica", "wellsfargo", "sbi", "hdfcbank", "icicibank",
    "flipkart", "steam", "yahoo", "twitter", "instagram", "linkedin", "dropbox",
    "binance", "coinbase", "metamask", "whatsapp", "telegram"
]

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "url_entropy",
    "host_entropy",
    "is_ip_address",
    "subdomain_count",
    "hyphen_count_host",
    "dot_count_url",
    "digit_count_host",
    "suspicious_tld",
    "suspicious_char_count",
    "has_at_symbol",
    "has_double_slash_path",
    "is_punycode",
    "brand_similarity_score",
    "non_standard_port",
    "is_https",
    "external_form_action",
    "password_field_present",
    "phishing_keyword_count"
]


def shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def is_ip_host(host: str) -> int:
    """Detects standard IPv4, IPv6, or hex/octal encoded IP addresses."""
    if not host:
        return 0
    # Clean port if present
    h = host.split(":")[0]
    # IPv4 regex
    ipv4 = r"^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
    if re.match(ipv4, h):
        return 1
    # IPv6 format
    if ":" in h and any(c in "0123456789abcdefABCDEF" for c in h):
        return 1
    # Hex or octal (e.g. 0x7f.1 or 017700000001 or dword)
    if re.match(r"^0x[0-9a-fA-F]+", h) or (h.isdigit() and len(h) >= 8):
        return 1
    return 0


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def compute_brand_similarity(host: str) -> float:
    """
    Computes brand impersonation / typosquatting similarity.
    Returns value between 0.0 (no match) and 1.0 (strong spoofing match).
    """
    if not host:
        return 0.0
    clean_host = host.lower().replace("www.", "")
    # Check official domain match
    labels = clean_host.split(".")
    domain_body = labels[-2] if len(labels) >= 2 else labels[0]
    subparts = re.split(r"[-_]", domain_body)

    max_sim = 0.0
    for brand in MAJOR_BRANDS:
        # If it is identical to official brand body, only suspicious if extra subdomains or weird TLD
        if brand == domain_body:
            max_sim = max(max_sim, 0.3)
            continue

        # Look for subparts or typo
        for part in subparts:
            if not part:
                continue
            if brand in part:
                max_sim = max(max_sim, 0.85)
            else:
                dist = levenshtein_distance(part, brand)
                threshold = 2 if len(brand) > 5 else 1
                if dist <= threshold:
                    sim = 1.0 - (dist / max(len(part), len(brand)))
                    max_sim = max(max_sim, round(sim, 3))

    return round(max_sim, 3)


def extract_features(url: str, webpage_meta: dict = None) -> list:
    """
    Extracts 20 numerical features from a URL and optional webpage metadata.
    """
    meta = webpage_meta or {}
    url_str = str(url or "").strip()
    try:
        parsed = urlparse(url_str)
    except Exception:
        parsed = urlparse("")

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or parsed.netloc or "").lower()
    path = parsed.path or ""

    # Feature 1 & 2: Lengths
    url_len = len(url_str)
    host_len = len(host)

    # Feature 3 & 4: Entropies
    url_ent = shannon_entropy(url_str)
    host_ent = shannon_entropy(host)

    # Feature 5: IP Host
    is_ip = is_ip_host(host)

    # Feature 6: Subdomains count
    host_parts = host.split(".")
    subdomain_count = max(0, len(host_parts) - 2) if not is_ip else 0

    # Feature 7: Hyphens in host
    hyphens_host = host.count("-")

    # Feature 8: Dots in URL
    dots_url = url_str.count(".")

    # Feature 9: Digits in host
    digits_host = sum(c.isdigit() for c in host)

    # Feature 10: Suspicious TLD
    tld = host_parts[-1] if host_parts else ""
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Feature 11: Suspicious characters count
    suspicious_chars = sum(url_str.count(c) for c in ["@", "_", "%", "~", "!", "$", "*", "="])

    # Feature 12: @ symbol
    has_at = 1 if "@" in url_str else 0

    # Feature 13: Double slash in path
    has_double_slash = 1 if "//" in path else 0

    # Feature 14: Punycode
    is_puny = 1 if "xn--" in host else 0

    # Feature 15: Brand similarity
    brand_sim = compute_brand_similarity(host)

    # Feature 16: Non-standard port
    non_standard_port = 0
    if parsed.port and parsed.port not in [80, 443]:
        non_standard_port = 1

    # Feature 17: HTTPS
    is_https = 1 if scheme == "https" else 0

    # Feature 18, 19, 20: Webpage metadata features
    ext_form = 1 if meta.get("external_form_action") else 0
    pwd_present = 1 if meta.get("password_field_present") else 0
    keyword_count = int(meta.get("phishing_keyword_count", 0))

    return [
        url_len,
        host_len,
        url_ent,
        host_ent,
        is_ip,
        subdomain_count,
        hyphens_host,
        dots_url,
        digits_host,
        suspicious_tld,
        suspicious_chars,
        has_at,
        has_double_slash,
        is_puny,
        brand_sim,
        non_standard_port,
        is_https,
        ext_form,
        pwd_present,
        keyword_count
    ]
