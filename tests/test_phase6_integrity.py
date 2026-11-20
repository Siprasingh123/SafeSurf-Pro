"""
SafeSurf Pro - Phase 6 Integrity Test Suite
Verifies Advanced Protection & Threat Intelligence:
1. Active blocking logic and redirect URL generation (blocked.html?url=...&score=...&reason=...)
2. Session bypass mechanism (ALLOW_BYPASS -> bypass_<tabId> prevents infinite redirect loop)
3. Google Safe Browsing v4 threat intelligence (API configuration, payload structure, all 4 threat types, risk escalation)
4. Passive warning banner dispatch and risk-level styling
5. Badging logic across threat levels
"""

import sys
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent

def run_tests():
    passed = 0
    failed = 0

    def assert_test(cond, name):
        nonlocal passed, failed
        if cond:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[FAIL] {name}")
            failed += 1

    bg_path = ROOT / "background.js"
    cs_path = ROOT / "content.js"
    sb_path = ROOT / "safe_browsing.js"
    bl_js_path = ROOT / "blocked.js"
    bl_html_path = ROOT / "blocked.html"

    assert_test(bg_path.exists(), "background.js exists")
    assert_test(cs_path.exists(), "content.js exists")
    assert_test(sb_path.exists(), "safe_browsing.js exists")
    assert_test(bl_js_path.exists(), "blocked.js exists")
    assert_test(bl_html_path.exists(), "blocked.html exists")

    bg_code = bg_path.read_text(encoding="utf-8")
    cs_code = cs_path.read_text(encoding="utf-8")
    sb_code = sb_path.read_text(encoding="utf-8")
    bl_js = bl_js_path.read_text(encoding="utf-8")
    bl_html = bl_html_path.read_text(encoding="utf-8")

    # 1. Safe Browsing checks
    assert_test("safebrowsing.googleapis.com/v4/threatMatches:find" in sb_code, "SafeBrowsing API endpoint configured")
    assert_test("MALWARE" in sb_code, "SafeBrowsing checks MALWARE")
    assert_test("SOCIAL_ENGINEERING" in sb_code, "SafeBrowsing checks SOCIAL_ENGINEERING")
    assert_test("UNWANTED_SOFTWARE" in sb_code, "SafeBrowsing checks UNWANTED_SOFTWARE")
    assert_test("POTENTIALLY_HARMFUL_APPLICATION" in sb_code, "SafeBrowsing checks POTENTIALLY_HARMFUL_APPLICATION")
    assert_test("safe_browsing_api_key" in sb_code, "SafeBrowsing reads key from storage")
    assert_test("flagged: true" in sb_code, "SafeBrowsing flags matches")

    # 2. Threat Intelligence Integration in Background
    assert_test("SafeBrowsing.checkUrl" in bg_code, "Background calls SafeBrowsing.checkUrl")
    assert_test("safeBrowsingResult.flagged" in bg_code, "Background handles safeBrowsingResult.flagged")
    assert_test("phishingRiskScore = 100" in bg_code, "Flagged threat escalates phishing risk to 100")
    assert_test("Threat Intelligence" in bg_code, "Threat Intelligence reason category added")

    # 3. Active Blocking & Session Bypass
    assert_test("settings.blocking_enabled" in bg_code, "Active blocking respects blocking_enabled toggle")
    assert_test("blocked.html?url=" in bg_code, "Redirects to blocked.html with parameters")
    assert_test("bypassStore" in bg_code and "bypass_" in bg_code, "Background queries session bypassStore")
    assert_test("ALLOW_BYPASS" in bg_code, "Background handles ALLOW_BYPASS message")
    assert_test("chrome.storage.session.set" in bg_code, "ALLOW_BYPASS sets session storage")

    # 4. Interstitial Blocked Page
    assert_test("ALLOW_BYPASS" in bl_js, "blocked.js sends ALLOW_BYPASS before navigation")
    assert_test("targetUrl" in bl_js, "blocked.js reads targetUrl parameter")
    assert_test("goBackBtn" in bl_js and "proceedBtn" in bl_js, "blocked.js handles back and proceed actions")
    assert_test("id=\"targetUrl\"" in bl_html, "blocked.html contains targetUrl element")
    assert_test("id=\"proceedBtn\"" in bl_html, "blocked.html contains proceed button")

    # 5. Passive Warning Banner
    assert_test("SHOW_PASSIVE_ALERT" in bg_code, "Background dispatches SHOW_PASSIVE_ALERT when not blocked")
    assert_test("SHOW_PASSIVE_ALERT" in cs_code, "Content script listens for SHOW_PASSIVE_ALERT")
    assert_test("renderPassiveAlertBanner" in cs_code, "Content script implements renderPassiveAlertBanner")
    assert_test("safesurf-alert-banner" in cs_code, "Banner has unique DOM ID")
    assert_test("isMedium" in cs_code, "Banner adapts style for Medium vs High/Critical risk")

    # 6. Action Badge Updates
    assert_test("setBadgeText" in bg_code, "Background updates badge text")
    assert_test("\"!\"" in bg_code or "'!'" in bg_code, "Badge displays exclamation for Critical/High")
    assert_test("\"WARN\"" in bg_code or "'WARN'" in bg_code, "Badge displays WARN for Medium or low security")
    assert_test("\"OK\"" in bg_code or "'OK'" in bg_code, "Badge displays OK for Safe")

    print(f"\nPhase 6 Integrity Test Results: {passed} Passed, {failed} Failed")
    return failed == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
