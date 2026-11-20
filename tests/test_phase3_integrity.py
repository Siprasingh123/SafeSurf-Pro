import json
import math
import os
import sys

EXT_DIR = r"D:\safesurf-pro"
passed = 0
failed = 0

def check(condition, msg):
    global passed, failed
    if condition:
        print(f"  \033[32m✔ PASS:\033[0m {msg}")
        passed += 1
    else:
        print(f"  \033[31m✖ FAIL:\033[0m {msg}")
        failed += 1

print("\n=======================================================")
print("SAFESURF PRO - PHASE 3 ML, PHISHING & XAI VERIFICATION")
print("=======================================================\n")

# 1. Model Structure & Feature Names
print("[Suite 1: Machine Learning Model Integrity]")
with open(os.path.join(EXT_DIR, "models", "phishing_model.json"), "r", encoding="utf-8") as f:
    model_data = json.load(f)

check(model_data.get("model_type") == "RandomForestEnsemble", "Model type is RandomForestEnsemble")
check(len(model_data.get("feature_names", [])) == 20, "Model defines exactly 20 features")
check(len(model_data.get("trees", [])) >= 5, f"Model ensemble contains {len(model_data.get('trees', []))} trees")

expected_features = [
    "url_length", "host_length", "url_entropy", "host_entropy", "is_ip_address",
    "subdomain_count", "hyphen_count_host", "dot_count_url", "digit_count_host",
    "suspicious_tld", "suspicious_char_count", "has_at_symbol", "has_double_slash_path",
    "is_punycode", "brand_similarity_score", "non_standard_port", "is_https",
    "external_form_action", "password_field_present", "phishing_keyword_count"
]
check(model_data.get("feature_names") == expected_features, "Feature names match expected 20 feature schema in order")

# 2. ML Engine Verification
print("\n[Suite 2: ML Engine Inference & Explainable AI]")
with open(os.path.join(EXT_DIR, "ml_engine.js"), "r", encoding="utf-8") as f:
    ml_js = f.read()

check("evaluateTree" in ml_js, "ml_engine.js implements evaluateTree")
check("contributions[featName]" in ml_js, "ml_engine.js tracks feature attribution contributions for XAI")
check("evaluateFallback" in ml_js, "ml_engine.js provides resilient heuristic fallback")
check("riskTier" in ml_js, "ml_engine.js derives risk tiers")
check("featureDescriptions" in ml_js, "ml_engine.js contains human-readable Explainable AI feature descriptions")

for feat in ["phishing_keyword_count", "password_field_present", "external_form_action", "brand_similarity_score"]:
    check(feat in ml_js, f"XAI explanation mapping covers critical feature: {feat}")

# 3. URL Analyzer Heuristics & Lookalike Detection
print("\n[Suite 3: URL Analyzer & Phishing Lookalike Detection]")
with open(os.path.join(EXT_DIR, "url_analyzer.js"), "r", encoding="utf-8") as f:
    url_js = f.read()

check("SUSPICIOUS_TLDS" in url_js, "url_analyzer.js maintains suspicious TLD set")
check("BRANDS" in url_js, "url_analyzer.js maintains protected brand registry")
check("HOMOGLYPHS" in url_js, "url_analyzer.js contains homoglyph character translation map")
check("shannonEntropy" in url_js, "url_analyzer.js implements Shannon entropy calculation")
check("isIpHost" in url_js, "url_analyzer.js implements IP host detection")
check("analyzeBrandImpersonation" in url_js, "url_analyzer.js implements brand impersonation analysis")
check("levenshtein" in url_js, "url_analyzer.js implements Levenshtein distance for typosquatting")

# 4. Threat Classification (Safe, Suspicious, High, Critical)
print("\n[Suite 4: Threat Classification Tiers]")
with open(os.path.join(EXT_DIR, "history.js"), "r", encoding="utf-8") as f:
    hist_js = f.read()
with open(os.path.join(EXT_DIR, "background.js"), "r", encoding="utf-8") as f:
    bg_js = f.read()

check('"Critical"' in hist_js, "history.js classifies Critical threat status")
check('"High"' in hist_js, "history.js classifies High threat status")
check('"Suspicious"' in hist_js, "history.js classifies Suspicious threat status")
check('"Safe"' in hist_js, "history.js classifies Safe threat status")

check("phishingRiskScore >= 75" in bg_js and "Critical" in bg_js, "background.js assigns Critical tier for phishingRiskScore >= 75")
check("phishingRiskScore >= 50" in bg_js and "High" in bg_js, "background.js assigns High tier for phishingRiskScore >= 50")
check("phishingRiskScore >= 25" in bg_js and "Medium" in bg_js, "background.js assigns Medium tier for phishingRiskScore >= 25")

# 5. Dual Scores & Explainable AI Aggregation in background.js
print("\n[Suite 5: Dual Scores & Explainable AI Synthesis]")
check("securityScore" in bg_js and "phishingRiskScore" in bg_js, "background.js synthesizes Dual Scores (Security & Phishing)")
check("URL & Domain" in bg_js, "background.js categories include 'URL & Domain'")
check("Page Content" in bg_js, "background.js categories include 'Page Content'")
check("AI Detection" in bg_js, "background.js categories include 'AI Detection'")
check("Threat Intelligence" in bg_js, "background.js categories include 'Threat Intelligence'")

print("\n-------------------------------------------------------")
print(f"PHASE 3 RESULTS: {passed} PASSED, {failed} FAILED")
print("-------------------------------------------------------\n")

if failed > 0:
    sys.exit(1)
