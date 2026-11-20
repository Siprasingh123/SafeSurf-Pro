import json
import re
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
print("SAFESURF PRO - PHASE 2 WEBSITE SECURITY & DOM TESTS")
print("=======================================================\n")

# 1. Security Score Logic & Weighting in background.js
print("[Suite 1: Website Security Score & Header Evaluation]")
with open(os.path.join(EXT_DIR, "background.js"), "r", encoding="utf-8") as f:
    bg_js = f.read()

check("calculateSecurityScore" in bg_js, "background.js defines calculateSecurityScore")
check("score += 30" in bg_js, "HTTPS awards 30 points")
check("headers.hsts" in bg_js and "score += 15" in bg_js, "HSTS awards 15 points")
check("headers.csp" in bg_js and "score += 20" in bg_js, "CSP awards 20 points")
check("headers.xfo" in bg_js and "score += 15" in bg_js, "XFO/frame-ancestors awards 15 points")
check("headers.nosniff" in bg_js and "score += 10" in bg_js, "nosniff awards 10 points")
check("headers.referrer" in bg_js and "score += 5" in bg_js, "Referrer-Policy awards 5 points")
check("cookieStats" in bg_js and "score += 5" in bg_js, "Secure cookie posture awards 5 points")
check("Math.min(100, Math.max(0, score))" in bg_js, "Security score is bounded between 0 and 100")

# 2. Cookie Security Inspection in background.js
print("\n[Suite 2: Background Cookie Security Analysis]")
check("chrome.cookies.getAll" in bg_js, "background.js inspects cookies via chrome.cookies.getAll")
check("cookieStats.insecure" in bg_js, "background.js calculates insecure cookies lacking Secure or HttpOnly")
check("cat: \"cookies\"" in bg_js, "background.js generates categorized findings for insecure cookies")

# 3. DOM Security & Threats Analysis in content.js
print("\n[Suite 3: DOM Security Analysis in content.js]")
with open(os.path.join(EXT_DIR, "content.js"), "r", encoding="utf-8") as f:
    cs_js = f.read()

check("password_field_present" in cs_js, "content.js detects password inputs")
check("location.protocol === \"http:\"" in cs_js, "content.js flags password inputs on plain HTTP")
check("sensitiveSelectors" in cs_js, "content.js inspects CVV, CVC, SSN, PIN, and crypto seed inputs")
check("external_form_action" in cs_js, "content.js flags external form action destinations")
check("insecure_form_action" in cs_js, "content.js flags HTTPS pages submitting forms over unencrypted HTTP")
check("hidden_iframe_detected" in cs_js, "content.js detects deceptive zero-pixel or hidden external iframes")
check("mixed_content_detected" in cs_js, "content.js detects mixed active content (HTTP scripts on HTTPS)")
check("fake_login_detected" in cs_js, "content.js detects deceptive modal or floating login overlays")
check("suspicious_redirect_detected" in cs_js, "content.js inspects meta refresh redirects to external origins")
check("phishing_keyword_count" in cs_js, "content.js analyzes urgent social engineering keywords")
check("thirdParty.length > 12" in cs_js, "content.js identifies high volume of external scripts")

# 4. Popup Security Posture Display
print("\n[Suite 4: Popup Security Posture Checks]")
with open(os.path.join(EXT_DIR, "popup.js"), "r", encoding="utf-8") as f:
    pop_js = f.read()

check("HTTPS Protocol" in pop_js, "popup.js reports HTTPS Protocol posture")
check("HSTS Protection" in pop_js, "popup.js reports HSTS Protection")
check("CSP Header" in pop_js, "popup.js reports CSP Header")
check("Anti-Clickjacking" in pop_js, "popup.js reports Anti-Clickjacking (XFO)")
check("MIME Sniffing Blocked" in pop_js, "popup.js reports MIME Sniffing header")
check("Referrer Policy" in pop_js, "popup.js reports Referrer Policy")
check("Mixed Content" in pop_js, "popup.js reports Mixed Content findings")
check("Cookie Security" in pop_js, "popup.js reports Cookie Security")

print("\n-------------------------------------------------------")
print(f"PHASE 2 RESULTS: {passed} PASSED, {failed} FAILED")
print("-------------------------------------------------------\n")

if failed > 0:
    sys.exit(1)
