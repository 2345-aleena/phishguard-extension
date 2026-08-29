# 🛡️ PhishGuard — Real-Time Phishing Detection Browser Extension

A Chrome (Manifest V3) browser extension that detects phishing websites in
real time using a **hybrid detection engine**: instant rule-based heuristics
combined with an **on-device machine learning model** (via ONNX Runtime Web).
No browsing data ever leaves the user's device for the ML inference step.

## Why on-device ML?

Most phishing detectors either rely purely on blocklists (slow to update,
miss zero-day phishing sites) or send every URL you visit to a third-party
server (privacy concern). PhishGuard runs a trained classifier **directly in
the browser**, so detection is instant and private.

## Architecture

```
User navigates to a page
        │
        ▼
content.js  ──► scans DOM for credential/login forms
        │
        ▼
background.js (service worker)
        │
        ├─► heuristics.js        (rule-based, instant, 0 network calls)
        ├─► ml-inference.js      (ONNX Runtime Web, on-device model)
        └─► Safe Browsing API    (optional, external threat intel)
        │
        ▼
Combined risk score → verdict (safe / suspicious / dangerous)
        │
        ▼
Warning banner injected into page + popup dashboard updated
```

## Detection layers

| Layer | Signal | Weight |
|---|---|---|
| Heuristics | IP-based URLs, punycode/homograph domains, excessive subdomains, `@` obfuscation, suspicious TLDs, URL shorteners, brand typo-squatting (Levenshtein distance) | 60% |
| ML model | Random Forest classifier trained on lexical URL features, exported to ONNX | 40% |
| External | Google Safe Browsing API v4 (optional) | Override to 100 if flagged |

## Project structure

```
phishing-extension/
├── extension/          # The browser extension (MV3)
│   ├── manifest.json
│   ├── src/
│   │   ├── background.js     # Service worker — orchestrates detection
│   │   ├── content.js        # DOM scanning + warning banner injection
│   │   ├── heuristics.js     # Rule-based detection engine
│   │   ├── ml-inference.js   # ONNX Runtime Web integration
│   │   ├── popup.html/.js    # Extension dashboard UI
│   └── model/                # Trained ONNX model goes here
├── ml/                  # Model training pipeline
│   ├── train_model.py
│   └── requirements.txt
└── dataset/              # Place training CSVs here (not committed)
```

## Setup

### 1. Train the model
```bash
cd ml
pip install -r requirements.txt
python train_model.py --data ../dataset/phishing_urls.csv
```
This outputs `phishing_url_model.onnx` into `extension/model/`.

Recommended datasets: [PhishTank](https://phishtank.org/developer_info.php),
Kaggle phishing URL datasets, or the [Tranco](https://tranco-list.eu/) top
sites list for legitimate examples.

### 2. Build the extension
```bash
cd extension
npm install
npm run build
```

### 3. Load into Chrome
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

## Roadmap / stretch goals
- [ ] Visual brand-similarity detection (favicon/logo comparison)
- [ ] Firefox port (MV3 support)
- [ ] User-adjustable sensitivity threshold
- [ ] Local whitelist management UI
- [ ] Periodic model retraining pipeline via GitHub Actions

## Disclaimer
This is a research/educational security tool. It reduces phishing risk but
is not a substitute for safe browsing practices or enterprise-grade threat
intelligence.

## License
MIT
