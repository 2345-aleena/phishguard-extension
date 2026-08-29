"""
Trains a lightweight phishing-URL classifier and exports it to ONNX
so it can run fully client-side in the browser extension via
ONNX Runtime Web.

Dataset: expects a CSV with columns ['url', 'label'] where label is
1 = phishing, 0 = legitimate. Good sources:
  - PhishTank (https://phishtank.org/developer_info.php)
  - Kaggle "Phishing URL Dataset" (e.g. by taruntiwarihp / eswar)
  - Tranco top-1M list for legitimate URLs

Usage:
    python train_model.py --data dataset/phishing_urls.csv
"""

import argparse
import re
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

FEATURE_NAMES = [
    "url_length", "hostname_length", "dot_count", "hyphen_count",
    "at_count", "is_ip", "is_https", "subdomain_count",
    "query_param_signal", "has_punycode",
]


def extract_features(url: str) -> list:
    """Must stay in sync with extension/src/ml-inference.js extractFeatures()."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        1 if url.startswith("https:") else 0,
        max(hostname.count(".") - 1, 0),
        len(re.findall(r"[?&=]", url)),
        1 if "xn--" in hostname else 0,
    ]


def main(data_path: str, out_dir: str):
    df = pd.read_csv(data_path)
    df = df.dropna(subset=["url", "label"])

    X = np.array([extract_features(u) for u in df["url"]])
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=12, class_weight="balanced", random_state=42
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    # Export to ONNX for in-browser inference
    from skl2onnx import to_onnx
    onnx_model = to_onnx(
        clf, X_train[:1].astype(np.float32),
        target_opset=12,
        options={id(clf): {"zipmap": False}},
    )
    out_path = f"{out_dir}/phishing_url_model.onnx"
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"Saved ONNX model to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to CSV with 'url','label' columns")
    parser.add_argument("--out", default="../extension/model", help="Output directory for the ONNX model")
    args = parser.parse_args()
    main(args.data, args.out)
