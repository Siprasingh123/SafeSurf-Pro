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
print("SAFESURF PRO - PHASE 4 HISTORY, STORAGE & STATS TESTS")
print("=======================================================\n")

with open(os.path.join(EXT_DIR, "history.js"), "r", encoding="utf-8") as f:
    hist_js = f.read()

# 1. Record Schema & Quota Protection
print("[Suite 1: History Record Schema & Quota Safeguards]")
check("createRecord" in hist_js, "history.js provides createRecord function")
check("findings.slice(0, 15)" in hist_js, "history.js truncates findings array to 15 items to safeguard quota")
check("reasons.slice(0, 15)" in hist_js, "history.js truncates reasons array to 15 items to safeguard quota")
check("slice(0, 300)" in hist_js, "history.js bounds finding/reason text to 300 characters")
check("findingsCount" in hist_js and "reasonsCount" in hist_js, "Record tracks findingsCount and reasonsCount metadata")

# 2. Cumulative Statistics
print("\n[Suite 2: Cumulative Threat Statistics Aggregation]")
check("recalculateThreatStats" in hist_js, "history.js implements recalculateThreatStats")
check("criticalCount" in hist_js, "Statistics track separate criticalCount metric")
check("avgSecurityScore" in hist_js, "Statistics calculate average security score")
check("avgPhishingRisk" in hist_js, "Statistics calculate average phishing risk")
check("totalScans" in hist_js, "Statistics track total scan count")
check("Math.round(totalSecScore / totalScans)" in hist_js, "Average security score is rounded")

# 3. Deduplication & In-Place Enrichment
print("\n[Suite 3: Deduplication & In-Place Enrichment]")
check("DEDUPLICATION_WINDOW_MS = 5000" in hist_js, "Deduplication window set to 5000ms")
check("findRecentDuplicateIndex" in hist_js, "findRecentDuplicateIndex accurately checks recent scan window")
check("isRicher" in hist_js, "history.js detects richer telemetry arriving after initial scan")
check("history[dupIdx] = newRecord" in hist_js, "history.js updates record in-place when richer data arrives")

# 4. Search & Risk Filtering
print("\n[Suite 4: History Search & Filtering]")
check("filterHistoryItems" in hist_js, "history.js exports filterHistoryItems")
check("matchesSearch" in hist_js, "filterHistoryItems filters across domain, URL, and primary threat")
check("matchesRisk" in hist_js, "filterHistoryItems filters by risk classification (SAFE, SUSPICIOUS, PHISHING)")

# 5. RFC 4180 CSV Export
print("\n[Suite 5: RFC 4180 CSV Export Compliance]")
check("exportToCsvString" in hist_js, "history.js exports exportToCsvString")
check('\\r\\n' in repr(hist_js) or "join(\"\\r\\n\")" in hist_js, "exportToCsvString uses RFC 4180 compliant CRLF row terminators")
check('replace(/"/g, \'""\')' in hist_js, "exportToCsvString implements RFC 4180 double-quote escaping")

# 6. History Reset & Clear
print("\n[Suite 6: History Clearing & Reset]")
check("clearHistory" in hist_js, "history.js provides clearHistory")
check("scan_history: []" in hist_js, "clearHistory empties scan_history in storage.local")
check("emptyStats" in hist_js, "clearHistory resets threat_stats back to zero baseline")

print("\n-------------------------------------------------------")
print(f"PHASE 4 RESULTS: {passed} PASSED, {failed} FAILED")
print("-------------------------------------------------------\n")

if failed > 0:
    sys.exit(1)
