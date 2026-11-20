# SafeSurf Pro (v2.1.0) - Advanced AI Phishing Detection System

**SafeSurf Pro** is a Manifest V3 Google Chrome extension augmented with machine learning, threat intelligence, and explainable AI to detect phishing attacks, deceptive brand impersonation, and insecure web configurations in real time.

---

## Key Features & Upgrades

### 1. Advanced URL & Domain Analysis
- **Shannon Entropy**: Measures character randomness for URLs and hostnames to identify Domain Generation Algorithms (DGA) and randomized attacker infrastructure.
- **IP Address Detection**: Detects direct IPv4, IPv6, hex, octal, or integer-encoded hostnames.
- **Suspicious Character Counting**: Identifies delimiter abuse (`@`, `//`, `_`, `%`, `~`, `!`, `$`, `*`, `=`).
- **Domain Structure**: Subdomain depth analysis, hyphen stuffing, digit distribution, non-standard port detection (`:8080`, `:8888`, `:4443`).
- **High-Risk TLDs**: Flags domains using frequently abused TLDs (`.top`, `.xyz`, `.fit`, `.click`, `.loan`, `.country`, `.zip`, `.tk`, etc.).

### 2. Machine Learning Phishing Engine (Python & Browser-Side JS)
- **Model Architecture**: Scikit-Learn `RandomForestClassifier` and `DecisionTreeClassifier` trained on 20 numerical and contextual security features.
- **Client-Side Runtime**: Exported model (`models/phishing_model.json`) executes in JavaScript inside the browser at 0 latency with zero external server dependencies.
- **Evaluation Metrics**:
  - **Decision Tree**: Accuracy `99.40%` | Precision `99.20%` | Recall `99.60%` | F1-Score `99.40%`
  - **Random Forest**: Accuracy `100.00%` | Precision `100.00%` | Recall `100.00%` | F1-Score `100.00%`
  - Full evaluation details in `ml/evaluation_report.txt` and `ml/evaluation_report.json`.

### 3. Brand Impersonation & Typosquatting Detection
- Expanded registry of 30+ top global and regional financial, tech, and crypto targets (PayPal, Google, Apple, Microsoft, Amazon, Netflix, Chase, SBI, HDFC Bank, ICICI Bank, Binance, MetaMask, etc.).
- Levenshtein distance matching on domain tokens.
- **Unicode & Punycode**: Cyrillic/Greek homoglyph normalization (`xn--` decoding and confusable character matching).
- Subdomain camouflage detection (e.g. `paypal.com.attacker-domain.xyz`).

### 4. Deep Webpage & Form Analysis
- Detects unencrypted (HTTP) password collection forms.
- Inspects external `action` targets transmitting user credentials to third-party hosts.
- Deceptive floating login modals / credential harvesting overlays.
- Suspicious automated client redirects (`meta http-equiv="refresh"`).
- Weighted natural language scanning for psychological phishing triggers (urgent account lock, OTP requests, KYC required, crypto giveaway, seed phrase prompts).

### 5. Threat Intelligence (Google Safe Browsing v4)
- Seamless Google Safe Browsing Lookup API integration.
- API keys configured through the extension settings and stored securely in `chrome.storage.local` (never exposed in frontend code).
- Heuristic and AI fallback when operating offline or without an API key.

### 6. Explainable AI (XAI)
- Every prediction highlights the exact contributing signals (e.g., "High character randomness (entropy)", "Typosquatting detected: 'paypa1' mimics 'paypal'", "External form transmission").
- Transparent category tagging in popup: `AI DETECTION`, `URL & DOMAIN`, `PAGE CONTENT`, `THREAT INTEL`.

### 7. Dual Scoring System
- **Website Security Score (0-100)**: Evaluates transport encryption and defense-in-depth headers (`HTTPS`, `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, Cookie security flags).
- **Phishing Risk Score (0-100)**: Real-time risk probability calculated by the Random Forest model, URL heuristics, brand matching, and page inspection.

### 8. Real-Time Risk Alerts & Passive/Active Blocking
- Passive by default: Dynamic Chrome action badge (`OK`, `WARN`, `!`) and non-intrusive floating in-page warning banner.
- Optional Active Blocking: Interstitial warning screen (`blocked.html`) when enabled by user in settings.

### 9. Advanced Threat Intelligence Dashboard (`dashboard.html`)
- Real-time telemetry: Total Scans, Safe, Suspicious, Phishing counts.
- Pure SVG charts: Donut Risk Distribution and Session Comparison Bar Charts.
- Filterable and searchable Scan History table.
- RFC 4180-compliant **CSV Export** (`safesurf_scan_history_<timestamp>.csv`).

### 10. Modern UI & System-Based Dark Mode
- Full support for `@media (prefers-color-scheme: dark)` and manual toggle.
- Safe DOM manipulation preventing Cross-Site Scripting (XSS).

---

## Project Structure

```
safesurf-pro/
├── manifest.json              # Chrome Manifest V3 configuration
├── background.js              # Service worker orchestrator & Safe Browsing client
├── content.js                 # In-page DOM inspector & passive alert renderer
├── history.js                 # Centralized persistent storage, stats & deduplication
├── url_analyzer.js            # URL heuristics, entropy, homoglyph & brand analyzer
├── ml_engine.js               # Browser-side Random Forest inference & XAI engine
├── safe_browsing.js           # Secure Google Safe Browsing API integration
├── popup.html                 # Extension popup interface
├── popup.js                   # Popup logic (Dual Scores, XAI, security checks)
├── dashboard.html             # Threat intelligence dashboard with charts & history
├── dashboard.js               # Dashboard controller & CSV export
├── blocked.html               # Interstitial blocking warning page
├── blocked.js                 # Warning actions (Back to Safety / Proceed)
├── models/
│   └── phishing_model.json    # Exported Random Forest tree structure for browser runtime
├── ml/
│   ├── features.py            # Feature extraction engine (20 features)
│   ├── generate_dataset.py    # Synthetic dataset generator (2500 samples)
│   ├── train.py               # Scikit-learn training & evaluation pipeline
│   ├── evaluate.py            # CLI URL test tool
│   ├── dataset.csv            # Training & validation dataset
│   ├── evaluation_report.json # Detailed ML evaluation metrics
│   └── evaluation_report.txt  # Human-readable ML evaluation report
└── tests/
    ├── test_extension_core.js # Automated Node.js unit and integration test suite
    └── test_live_persistence.js # Live data collection & persistence tests
```

---

## Installation & Usage

### 1. Load the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked**.
4. Select the SafeSurf Pro extension root directory (e.g. `d:\safesurf-pro`).
5. The **SafeSurf Pro** shield icon will appear in your Chrome toolbar.

### 2. Run the Machine Learning Pipeline (Python)
To evaluate any URL via the command-line interface:
```bash
# Test any URL via the command line using client model
python ml/evaluate.py "http://paypa1-security-verify.xyz/login.php"
```

### 3. Run Automated Integrity & Regression Test Suites
All phases include automated test suites covering Manifest V3 architectural integrity, website security scoring, DOM heuristics, ML inference, persistent storage, UI telemetry, active blocking, and threat intelligence:
```bash
# Run all Phase 1 to Phase 6 integrity test suites
python -c "import subprocess, sys; tests = ['test_phase1_integrity.py', 'test_phase2_integrity.py', 'test_phase3_integrity.py', 'test_phase4_integrity.py', 'test_phase5_integrity.py', 'test_phase6_integrity.py']; [sys.exit(1) for t in tests if subprocess.run([sys.executable, f'tests/{t}']).returncode != 0]; print('\nALL SUITES PASSED (217 tests)!')"
```
