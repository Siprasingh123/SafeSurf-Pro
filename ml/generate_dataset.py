"""
SafeSurf Pro - Phishing Dataset Generator
Generates a representative, balanced synthetic dataset of legitimate and phishing samples
covering modern evasion techniques, typosquatting, TLD abuse, and credential harvesting.
"""

import csv
import os
import random
from features import extract_features, FEATURE_NAMES

LEGITIMATE_DOMAINS = [
    "google.com", "google.co.in", "youtube.com", "facebook.com", "amazon.com",
    "amazon.in", "wikipedia.org", "yahoo.com", "reddit.com", "netflix.com",
    "microsoft.com", "live.com", "apple.com", "github.com", "linkedin.com",
    "twitter.com", "instagram.com", "paypal.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com",
    "flipkart.com", "nytimes.com", "bbc.com", "cnn.com", "stanford.edu",
    "mit.edu", "gov.in", "whitehouse.gov", "nih.gov", "mozilla.org",
    "stackoverflow.com", "docker.com", "cloudflare.com", "dropbox.com", "salesforce.com"
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products", "/features", "/pricing",
    "/docs/v1/api", "/blog/security-updates", "/help/article/10492",
    "/search?q=machine+learning", "/category/technology", "/watch?v=dQw4w9WgXcQ",
    "/profile/settings", "/download/installer", "/terms-of-service", "/privacy"
]

PHISHING_BRANDS = [
    "paypal", "google", "amazon", "apple", "netflix", "microsoft", "chase",
    "sbi", "hdfcbank", "icicibank", "facebook", "binance", "metamask", "coinbase"
]

PHISHING_TLDS = ["xyz", "top", "click", "loan", "work", "fit", "country", "zip", "tk", "ml", "ga"]

PHISHING_PATH_COMPONENTS = [
    "verify-account", "security-check", "update-billing", "confirm-identity",
    "login-resolution", "unusual-activity", "restore-access", "wallet-validation",
    "auth/login.php", "secure-portal/index.html", "session-expired", "kyc-document-upload"
]


def generate_legitimate_samples(count=1200):
    samples = []
    for _ in range(count):
        domain = random.choice(LEGITIMATE_DOMAINS)
        sub = ""
        if random.random() < 0.25:
            sub = random.choice(["www.", "app.", "api.", "docs.", "my.", "support.", "portal."])
        path = random.choice(LEGIT_PATHS)
        query = ""
        if random.random() < 0.3:
            query = f"?ref=homepage&lang=en&sid={random.randint(1000, 9999)}"
        scheme = "https" if random.random() > 0.05 else "http"
        url = f"{scheme}://{sub}{domain}{path}{query}"

        meta = {
            "external_form_action": 0 if random.random() > 0.02 else 1,
            "password_field_present": 1 if "/login" in path or "/settings" in path else 0,
            "phishing_keyword_count": 0 if random.random() > 0.05 else 1
        }
        samples.append((url, meta, 0))  # 0 = Legitimate
    return samples


def generate_phishing_samples(count=1200):
    samples = []
    for _ in range(count):
        brand = random.choice(PHISHING_BRANDS)
        tld = random.choice(PHISHING_TLDS)
        attack_type = random.choice([
            "typosquat", "subdomain_spoof", "ip_address", "random_entropy",
            "punycode", "hyphen_brand", "non_standard_port"
        ])

        scheme = "http" if random.random() < 0.55 else "https"
        meta = {
            "external_form_action": 1 if random.random() < 0.70 else 0,
            "password_field_present": 1 if random.random() < 0.85 else 0,
            "phishing_keyword_count": random.randint(1, 4)
        }

        if attack_type == "typosquat":
            # Typos: replace o->0, l->1, or add subtle characters
            typo_brand = brand.replace("o", "0").replace("l", "1").replace("e", "3")
            if typo_brand == brand:
                typo_brand = brand + "s"
            url = f"{scheme}://{typo_brand}-{random.choice(['verify', 'secure', 'alert'])}.{tld}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        elif attack_type == "subdomain_spoof":
            # Real brand in subdomain on attacker domain
            attacker_domain = f"auth-service-{random.randint(10, 999)}.{tld}"
            url = f"{scheme}://{brand}.com.{attacker_domain}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        elif attack_type == "ip_address":
            # Direct IP usage
            ip = f"{random.randint(11, 218)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8888, 4443, 7777])}" if random.random() < 0.4 else ""
            url = f"http://{ip}{port}/{brand}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        elif attack_type == "random_entropy":
            # Random high-entropy token domain
            token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
            url = f"{scheme}://{token}.{tld}/{brand}-login.php?user_id={random.randint(100000, 999999)}"

        elif attack_type == "punycode":
            # Punycode homoglyph attack
            url = f"{scheme}://xn--{brand}6xa.{tld}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        elif attack_type == "hyphen_brand":
            # Multiple hyphens and keyword stuffing
            url = f"{scheme}://secure-login-{brand}-account-security-update.{tld}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        else:  # non_standard_port
            url = f"{scheme}://portal-{brand}.{tld}:{random.choice([8080, 8443, 3000, 9000])}/{random.choice(PHISHING_PATH_COMPONENTS)}"

        samples.append((url, meta, 1))  # 1 = Phishing
    return samples


def generate_dataset(csv_path="ml/dataset.csv"):
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    legit = generate_legitimate_samples(1250)
    phish = generate_phishing_samples(1250)
    all_samples = legit + phish
    random.seed(42)
    random.shuffle(all_samples)

    header = FEATURE_NAMES + ["label"]
    rows = []
    for url, meta, label in all_samples:
        features = extract_features(url, meta)
        rows.append(features + [label])

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

    print(f"[Dataset] Generated {len(rows)} samples ({len(legit)} benign, {len(phish)} phishing) -> {csv_path}")
    return csv_path


if __name__ == "__main__":
    generate_dataset()
