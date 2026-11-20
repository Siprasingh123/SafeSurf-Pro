import json
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
print("SAFESURF PRO - PHASE 5 POPUP & DASHBOARD UI TESTS")
print("=======================================================\n")

with open(os.path.join(EXT_DIR, "popup.html"), "r", encoding="utf-8") as f:
    pop_html = f.read()
with open(os.path.join(EXT_DIR, "popup.js"), "r", encoding="utf-8") as f:
    pop_js = f.read()
with open(os.path.join(EXT_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
    dash_html = f.read()
with open(os.path.join(EXT_DIR, "dashboard.js"), "r", encoding="utf-8") as f:
    dash_js = f.read()

# 1. Popup UI & Elements
print("[Suite 1: Popup UI Components & Dual Scores]")
check("id=\"securityScore\"" in pop_html, "popup.html defines securityScore container")
check("id=\"phishingScore\"" in pop_html, "popup.html defines phishingScore container")
check("id=\"statusBadge\"" in pop_html, "popup.html defines statusBadge container")
check("id=\"xaiList\"" in pop_html, "popup.html defines xaiList container for Explainable AI")
check("id=\"checksList\"" in pop_html, "popup.html defines checksList container for Security Posture")
check("id=\"blockingToggle\"" in pop_html, "popup.html defines blockingToggle checkbox")
check("id=\"openDashboardBtn\"" in pop_html, "popup.html defines openDashboardBtn")
check("id=\"themeToggle\"" in pop_html, "popup.html defines themeToggle button")

# 2. Popup JavaScript Logic & Live Reactivity
print("\n[Suite 2: Popup Live Reactivity & Synchronized Controls]")
check("renderScanData" in pop_js, "popup.js provides renderScanData function")
check("norm(s.url) !== currentNorm" in pop_js, "popup.js validates session scan URL freshness")
check("new URL(h.url).origin !== url.origin" in pop_js, "popup.js validates session header origin freshness")
check("chrome.tabs.create({ url: chrome.runtime.getURL(\"dashboard.html\") })" in pop_js, "popup.js opens dashboard tab")
check("changes.blocking_enabled" in pop_js, "popup.js reactively synchronizes blocking toggle changes")
check("changes.theme_preference" in pop_js, "popup.js reactively synchronizes theme changes")

# 3. Dashboard Real-Time Telemetry & Counters
print("\n[Suite 3: Dashboard Telemetry & Real-Time Counters]")
for stat_id in ["statTotal", "statSafe", "statSuspicious", "statPhishing"]:
    check(f'id="{stat_id}"' in dash_html, f"dashboard.html defines counter #{stat_id}")

check("updateUI()" in dash_js, "dashboard.js implements updateUI")
check("statTotal" in dash_js and "statSafe" in dash_js, "dashboard.js dynamically updates all counters")
check("changes.scan_history" in dash_js and "changes.threat_stats" in dash_js, "dashboard.js listens to scan_history & threat_stats changes")

# 4. Dashboard SVG Visual Charts
print("\n[Suite 4: Dashboard SVG Visual Charts]")
check("id=\"pieChartSvg\"" in dash_html, "dashboard.html defines pieChartSvg for donut chart")
check("id=\"barChartSvg\"" in dash_html, "dashboard.html defines barChartSvg for score comparison")
check("renderDonutChart" in dash_js, "dashboard.js implements renderDonutChart")
check("renderBarChart" in dash_js, "dashboard.js implements renderBarChart")
check("stroke-dasharray" in dash_js, "renderDonutChart generates accurate SVG donut arcs")
check("rect" in dash_js and "#10b981" in dash_js, "renderBarChart draws comparative SVG score bars")

# 5. Dashboard Table, Filter & Settings
print("\n[Suite 5: Dashboard Table, Search & Settings]")
check("id=\"historyTableBody\"" in dash_html, "dashboard.html defines historyTableBody")
check("id=\"searchInput\"" in dash_html, "dashboard.html defines searchInput")
check("id=\"riskFilter\"" in dash_html, "dashboard.html defines riskFilter")
check("id=\"exportCsvBtn\"" in dash_html, "dashboard.html defines exportCsvBtn")
check("id=\"clearHistoryBtn\"" in dash_html, "dashboard.html defines clearHistoryBtn")
check("id=\"apiKeyInput\"" in dash_html, "dashboard.html defines apiKeyInput")
check("id=\"dashBlockingToggle\"" in dash_html, "dashboard.html defines dashBlockingToggle")

check("filterHistory" in dash_js, "dashboard.js implements filterHistory")
check("exportToCsv" in dash_js, "dashboard.js implements exportToCsv")
check("clearHistory" in dash_js, "dashboard.js implements clearHistory")
check("initSettings" in dash_js, "dashboard.js implements initSettings with Safe Browsing key & blocking toggle")
check("changes.theme_preference" in dash_js, "dashboard.js reactively synchronizes theme changes")
check("changes.blocking_enabled" in dash_js, "dashboard.js reactively synchronizes blocking toggle changes")

print("\n-------------------------------------------------------")
print(f"PHASE 5 RESULTS: {passed} PASSED, {failed} FAILED")
print("-------------------------------------------------------\n")

if failed > 0:
    sys.exit(1)
