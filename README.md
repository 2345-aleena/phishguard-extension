# 🛡️ PhishGuard — Real-Time Phishing Detection Browser Extension

A Chrome (Manifest V3) browser extension that detects phishing websites **in real time**, combining instant rule-based heuristics with an **on-device machine learning model** — no browsing data ever leaves your device, and no click is required: dangerous sites are flagged automatically the moment they load.

![Status](https://img.shields.io/badge/status-working%20demo-brightgreen)
![Manifest](https://img.shields.io/badge/manifest-v3-blue)
![ML](https://img.shields.io/badge/ML-Random%20Forest-orange)
![Privacy](https://img.shields.io/badge/inference-100%25%20on--device-purple)

---

## 🎥 Demo

> _Add a screen-recording GIF or short video here showing the red warning banner appearing automatically on a suspicious site._

| Safe site | Dangerous site |
|---|---|
| ✅ Green banner, low risk score | 🚫 Red banner auto-appears, reasons listed |

---

## Why this project

Most phishing detectors are either static blocklists (miss brand-new phishing sites) or send every URL you visit to a third-party server (privacy concern). PhishGuard runs a trained classifier **directly in the browser** — detection is instant, private, and works even on sites no blocklist has seen yet.

## How it works

```
User navigates to a page
        │
        ▼
content.js  ──► scans DOM for login/credential forms, reports the URL
        │
        ▼
background.js (service worker)
        │
        ├─► heuristics.js     → instant rule-based scoring (0 network calls)
        └─► ml-inference.js   → on-device Random Forest, pure JS, no WASM
        │
        ▼
Combined risk score → verdict (safe / suspicious / dangerous)
        │
        ▼
Red/amber warning banner auto-injected into the page + popup dashboard updated
```

### Detection layers

| Layer | Signal | Weight |
|---|---|---|
| **Heuristics** | Raw IP URLs, punycode/homograph domains, excessive subdomains, `@` obfuscation, suspicious TLDs, URL shorteners, brand typo-squatting (Levenshtein distance) | 60% |
| **ML model** | Random Forest trained on 16 lexical/structural URL features (entropy, digit ratio, path depth, vowel/consonant ratio, etc.) | 40% |

## The ML pipeline

The model wasn't just `RandomForestClassifier()` with defaults. The training pipeline:

1. **Compared 6 algorithm families** head-to-head via 5-fold stratified cross-validation: Logistic Regression, SVM (RBF), Random Forest, Gradient Boosting, XGBoost, and an ANN (MLP)
2. **Hyperparameter-tuned** the deployed model via `RandomizedSearchCV` (25 candidates × 5 folds) rather than using library defaults
3. **Caught and fixed a real data-leakage bug** during development — an early version of the dataset labeled every phishing URL as `http://` and every legitimate URL as `https://`, so the model learned to shortcut on protocol alone instead of genuine phishing patterns. Removed protocol as a feature and retrained.
4. **Held-out test set evaluated once**, at the end, on the final tuned model only

**Final performance** (held-out test set): **97% accuracy, 0.985 ROC-AUC**, 86–89% recall on the harder minority class (phishing).

### Why plain JS instead of ONNX Runtime Web

The original plan used ONNX Runtime Web for the on-device model. In practice, Chrome's Manifest V3 service worker environment blocks the dynamic `import()` that ONNX Runtime Web's WASM loader depends on — even after moving the workload to a Chrome "offscreen document" (the officially recommended workaround), the WASM glue module still failed to load reliably.

Rather than fight the platform, the model was **exported as a plain JSON tree structure** (`ml/export_forest_json.py`) and evaluated with a ~30-line hand-written JS tree-walker (`extension/src/ml-inference.js`) — no WASM, no dynamic imports, no offscreen document. Same trained model, same accuracy, a fraction of the size (211KB vs. 14MB), and it just works.

## Project structure

```
phishing-extension/
├── extension/              # The browser extension (MV3)
│   ├── manifest.json
│   ├── icons/
│   ├── model/
│   │   └── forest_model.json   # Trained model, exported as plain JSON
│   └── src/
│       ├── background.js       # Service worker — orchestrates detection
│       ├── content.js          # DOM scanning + auto warning banner
│       ├── heuristics.js       # Rule-based detection engine
│       ├── ml-inference.js     # Pure-JS decision forest evaluator
│       ├── popup.html/.js      # Extension dashboard UI
├── ml/                      # Model training pipeline
│   ├── train_model.py          # Feature extraction, algorithm comparison, tuning
│   └── export_forest_json.py   # Trains + exports the deployed model
└── dataset/                  # Training data (phishing + legitimate URLs)
```

## Setup

### 1. Train the model (optional — a trained model is already included)
```bash
cd ml
pip install -r requirements.txt
python export_forest_json.py --data ../dataset/phishing_urls_combined.csv
```

### 2. Load into Chrome
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

No build step required — the extension runs directly from source.

## Roadmap / stretch goals

- [ ] Visual brand-similarity detection (favicon/logo comparison)
- [ ] Google Safe Browsing API integration for external threat intel
- [ ] Firefox port
- [ ] User-adjustable sensitivity threshold
- [ ] Periodic model retraining pipeline

## Disclaimer

This is a research/educational security tool. It reduces phishing risk but is not a substitute for safe browsing practices or enterprise-grade threat intelligence.

## License

MIT
