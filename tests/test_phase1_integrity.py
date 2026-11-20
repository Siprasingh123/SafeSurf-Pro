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
print("SAFESURF PRO - PHASE 1 ARCHITECTURAL & COMPONENT TESTS")
print("=======================================================\n")

# 1. Manifest V3 Integrity
print("[Suite 1: Manifest V3 Structure & Permissions]")
with open(os.path.join(EXT_DIR, "manifest.json"), "r", encoding="utf-8") as f:
    manifest = json.load(f)

check(manifest.get("manifest_version") == 3, "Manifest version is 3")
check(manifest.get("name") == "SafeSurf Pro", "Manifest name is SafeSurf Pro")
check(manifest.get("background", {}).get("service_worker") == "background.js", "Background service worker configured as background.js")
perms = manifest.get("permissions", [])
for p in ["webRequest", "storage", "tabs", "cookies"]:
    check(p in perms, f"Permission '{p}' is declared")
war = manifest.get("web_accessible_resources", [])
war_files = []
for entry in war:
    war_files.extend(entry.get("resources", []))
for rf in ["dashboard.html", "blocked.html", "models/phishing_model.json"]:
    check(rf in war_files, f"Web accessible resource '{rf}' is registered")

# 2. Dashboard HTML/JS Binding
print("\n[Suite 2: Dashboard DOM & Event ID Consistency]")
with open(os.path.join(EXT_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
    dash_html = f.read()
with open(os.path.join(EXT_DIR, "dashboard.js"), "r", encoding="utf-8") as f:
    dash_js = f.read()

dash_required_ids = [
    "statTotal", "statSafe", "statSuspicious", "statPhishing",
    "pieChartSvg", "pieLegend", "barChartSvg", "historyCount",
    "searchInput", "riskFilter", "historyTableBody", "apiKeyInput",
    "saveApiKeyBtn", "dashBlockingToggle", "themeToggleBtn",
    "exportCsvBtn", "clearHistoryBtn"
]
for elem_id in dash_required_ids:
    check(f'id="{elem_id}"' in dash_html, f"dashboard.html contains element id='{elem_id}'")

check("chrome.storage.onChanged.addListener" in dash_js, "dashboard.js has real-time storage observer")
check("updateUI()" in dash_js, "dashboard.js defines updateUI for reactive rendering")
check("renderDonutChart" in dash_js, "dashboard.js has renderDonutChart")
check("renderBarChart" in dash_js, "dashboard.js has renderBarChart")
check("exportToCsv" in dash_js, "dashboard.js has exportToCsv")

# 3. Popup HTML/JS Binding
print("\n[Suite 3: Popup DOM & Stale Cache Protection]")
with open(os.path.join(EXT_DIR, "popup.html"), "r", encoding="utf-8") as f:
    pop_html = f.read()
with open(os.path.join(EXT_DIR, "popup.js"), "r", encoding="utf-8") as f:
    pop_js = f.read()

pop_required_ids = [
    "site", "securityScore", "phishingScore", "phishingSub",
    "statusBadge", "xaiList", "reasonsCount", "checksList",
    "foot", "themeToggle", "blockingToggle", "openDashboardBtn"
]
for elem_id in pop_required_ids:
    check(f'id="{elem_id}"' in pop_html, f"popup.html contains element id='{elem_id}'")

check("norm(s.url) !== currentNorm" in pop_js, "popup.js validates cached scan URL against active tab to eliminate stale display")
check("new URL(h.url).origin !== url.origin" in pop_js, "popup.js validates cached header origin against active tab")

# 4. Background & Content Script Messaging & Timing
print("\n[Suite 4: Background Service Worker & Content Script Communication]")
with open(os.path.join(EXT_DIR, "background.js"), "r", encoding="utf-8") as f:
    bg_js = f.read()
with open(os.path.join(EXT_DIR, "content.js"), "r", encoding="utf-8") as f:
    cs_js = f.read()

check("chrome.storage.session.remove" in bg_js, "background.js clears tab session cache on new navigation URL")
check("tabScanDebounce" in bg_js, "background.js utilizes debounce timer on complete navigation")
check("initialScanScheduled" in cs_js, "content.js uses single execution guard for initial page scan")
check("isScanning" in cs_js, "content.js guards against concurrent duplicate scans")
check("REQUEST_PAGE_SCAN" in bg_js and "REQUEST_PAGE_SCAN" in cs_js, "Bidirectional REQUEST_PAGE_SCAN contract present")

# 5. History Manager Deduplication & Enrichment
print("\n[Suite 5: HistoryManager Storage & Enrichment Logic]")
with open(os.path.join(EXT_DIR, "history.js"), "r", encoding="utf-8") as f:
    hist_js = f.read()

check("findRecentDuplicateIndex" in hist_js, "history.js implements recent duplicate index lookup")
check("isRicher" in hist_js, "history.js upgrades existing scan when rich DOM findings arrive")
check("exportToCsvString" in hist_js, "history.js exports RFC 4180 CSV string")
check("recalculateThreatStats" in hist_js, "history.js provides stat recalculation")

print("\n-------------------------------------------------------")
print(f"RESULTS: {passed} PASSED, {failed} FAILED")
print("-------------------------------------------------------\n")

if failed > 0:
    sys.exit(1)
