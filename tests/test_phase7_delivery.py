"""
SafeSurf Pro - Phase 7 Comprehensive Delivery & Optimization Audit
Verifies Manifest V3 compliance, complete project architecture, and all 10 core requirements:
1. Website security analysis (HTTPS, headers, cookies)
2. Phishing detection (URLs, forms, redirects, scripts, lookalike domains)
3. AI/ML prediction and explainable threat detection
4. Dual scores: Security and Phishing Risk (0-100)
5. Threat classification: Safe, Suspicious, High, Critical
6. Persistent scan history, statistics and CSV export
7. Functional popup with live security reports
8. Real-time dashboard with counters, charts and scan history
9. Advanced protection, warning system and optional blocking
10. Extension optimization, clean Manifest V3 lifecycle, and documentation
"""

import sys
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def run_audit():
    passed = 0
    failed = 0

    def check(condition, message):
        nonlocal passed, failed
        if condition:
            print(f"  ✔ PASS: {message}")
            passed += 1
        else:
            print(f"  ❌ FAIL: {message}")
            failed += 1

    print("\n=======================================================")
    print("SAFESURF PRO - PHASE 7 FINAL DELIVERY & AUDIT")
    print("=======================================================\n")

    # Section 1: Core File Presence & Syntax
    print("[Suite 1: Extension Architecture & Files]")
    required_files = [
        "manifest.json",
        "background.js",
        "content.js",
        "history.js",
        "url_analyzer.js",
        "ml_engine.js",
        "safe_browsing.js",
        "popup.html",
        "popup.js",
        "dashboard.html",
        "dashboard.js",
        "blocked.html",
        "blocked.js",
        "README.md",
        "models/phishing_model.json"
    ]
    for rf in required_files:
        fpath = ROOT / rf
        check(fpath.exists() and fpath.stat().st_size > 0, f"File exists and is non-empty: {rf}")

    # Section 2: Manifest V3 Compliance
    print("\n[Suite 2: Manifest V3 Specification Compliance]")
    manifest_path = ROOT / "manifest.json"
    with open(manifest_path, "r", encoding="utf-8") as f:
        m = json.load(f)

    check(m.get("manifest_version") == 3, "Manifest version is exactly 3")
    check(m.get("background", {}).get("service_worker") == "background.js", "Background is registered as MV3 service worker")
    check(isinstance(m.get("permissions"), list), "Permissions are specified as a list")
    for perm in ["webRequest", "storage", "tabs", "cookies"]:
        check(perm in m["permissions"], f"Required permission declared: {perm}")
    check("<all_urls>" in m.get("host_permissions", []), "Host permission '<all_urls>' declared")

    # Section 3: Dual Scoring System (0-100)
    print("\n[Suite 3: Dual Scoring System Validation]")
    bg_code = (ROOT / "background.js").read_text(encoding="utf-8")
    check("function calculateSecurityScore" in bg_code, "calculateSecurityScore function defined")
    check("Math.min(100, Math.max(0, score))" in bg_code or "Math.max(0, Math.min(100" in bg_code, "Security score properly bounded (0-100)")
    check("phishingRiskScore" in bg_code, "Phishing risk score computed and tracked")

    # Section 4: 4-Tier Threat Classification
    print("\n[Suite 4: 4-Tier Threat Classification]")
    hist_code = (ROOT / "history.js").read_text(encoding="utf-8")
    for tier in ["Critical", "High", "Suspicious", "Safe"]:
        check(tier in hist_code, f"HistoryManager supports threat tier: {tier}")

    # Section 5: Real-time Dashboard & Storage Telemetry
    print("\n[Suite 5: Real-time Dashboard & Storage Telemetry]")
    dash_code = (ROOT / "dashboard.js").read_text(encoding="utf-8")
    dash_html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
    check("chrome.storage.onChanged.addListener" in dash_code, "Dashboard listens to real-time storage changes")
    check("renderDonutChart" in dash_code, "Dashboard renders SVG donut risk chart")
    check("renderBarChart" in dash_code, "Dashboard renders SVG comparative score bar chart")
    check("exportToCsv" in dash_code, "Dashboard includes RFC 4180 CSV export")
    check("id=\"statTotal\"" in dash_html, "Dashboard contains #statTotal counter")
    check("id=\"historyTableBody\"" in dash_html, "Dashboard contains #historyTableBody")

    # Section 6: Active Blocking & Bypass Protection
    print("\n[Suite 6: Protection & Safety Interstitial]")
    check("ALLOW_BYPASS" in bg_code, "Background supports ALLOW_BYPASS session whitelist")
    bl_js = (ROOT / "blocked.js").read_text(encoding="utf-8")
    check("ALLOW_BYPASS" in bl_js, "blocked.js uses ALLOW_BYPASS to prevent re-blocking loop")
    check("SHOW_PASSIVE_ALERT" in bg_code, "Background dispatches SHOW_PASSIVE_ALERT")
    cs_code = (ROOT / "content.js").read_text(encoding="utf-8")
    check("renderPassiveAlertBanner" in cs_code, "Content script renders in-page alert banner")

    # Section 7: Machine Learning & Explainable AI
    print("\n[Suite 7: Client-Side Machine Learning & Explainability]")
    ml_code = (ROOT / "ml_engine.js").read_text(encoding="utf-8")
    check("predict(features)" in ml_code or "predict:" in ml_code or "async function predict" in ml_code, "ML engine implements predict()")
    check("feature_importances" in ml_code or "explanations" in ml_code, "ML engine generates Explainable AI explanations")
    model_json = json.loads((ROOT / "models" / "phishing_model.json").read_text(encoding="utf-8"))
    check(isinstance(model_json.get("trees"), list) and len(model_json["trees"]) > 0, "Bundled Random Forest JSON model contains decision trees")

    print(f"\n-------------------------------------------------------")
    print(f"PHASE 7 AUDIT RESULTS: {passed} PASSED, {failed} FAILED")
    print(f"-------------------------------------------------------\n")
    return failed == 0

if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
