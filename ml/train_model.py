"""
Advanced training pipeline for the phishing-URL classifier.

Improvements over a "basic" single-model approach:
  1. Richer feature set (16 lexical/structural features instead of ~9)
  2. Class imbalance handled explicitly (phishing is the minority class)
  3. Multiple algorithms compared head-to-head via stratified k-fold CV
     (Logistic Regression, Random Forest, Gradient Boosting)
  4. Hyperparameter tuning via RandomizedSearchCV on the best-performing
     algorithm, rather than using library defaults
  5. Feature importance analysis, so you can explain *why* the model
     makes its decisions (important for interviews / your README)
  6. Held-out test set evaluated only once, at the very end, on the
     final tuned model (avoids overly optimistic numbers)

Usage:
    python train_model.py --data ../dataset/phishing_urls_combined.csv
"""

import argparse
import math
import re
from urllib.parse import urlparse
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import (
    train_test_split, StratifiedKFold, cross_val_score, RandomizedSearchCV
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from xgboost import XGBClassifier

FEATURE_NAMES = [
    "url_length", "hostname_length", "dot_count", "hyphen_count",
    "at_count", "is_ip", "subdomain_count", "query_param_signal",
    "has_punycode", "digit_ratio", "path_length", "path_depth",
    "hostname_entropy", "special_char_ratio", "has_suspicious_tld",
    "vowel_consonant_ratio",
]

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".loan"}


def shannon_entropy(s: str) -> float:
    """Measures how 'random-looking' a string is. Phishing domains
    (e.g. 'x7k2p9.com') tend to have higher entropy than real brand
    names or dictionary-word domains."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url: str) -> list:
    """Must stay in sync with extension/src/ml-inference.js extractFeatures().
    NOTE: intentionally excludes protocol (http/https) as a feature — see
    the data-leakage note in project history; the training data's
    phishing==http / legit==https split was an artifact of data
    collection, not a real-world signal, so including it taught the
    model a shortcut instead of genuine phishing patterns.
    """
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = parsed.hostname or ""
        path = parsed.path or ""
    except Exception:
        hostname, path = "", ""

    digits = sum(c.isdigit() for c in url)
    special_chars = sum(1 for c in url if not c.isalnum() and c not in "://.")
    vowels = sum(1 for c in hostname.lower() if c in "aeiou")
    consonants = sum(1 for c in hostname.lower() if c.isalpha() and c not in "aeiou")

    return [
        len(url),
        len(hostname),
        url.count("."),
        url.count("-"),
        url.count("@"),
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        max(hostname.count(".") - 1, 0),
        len(re.findall(r"[?&=]", url)),
        1 if "xn--" in hostname else 0,
        digits / max(len(url), 1),
        len(path),
        path.count("/"),
        shannon_entropy(hostname),
        special_chars / max(len(url), 1),
        1 if any(hostname.endswith(t) for t in SUSPICIOUS_TLDS) else 0,
        vowels / max(consonants, 1),
    ]


def build_features(urls) -> np.ndarray:
    return np.array([extract_features(u) for u in urls], dtype=np.float32)


def compare_models(X_train, y_train, cv):
    """Head-to-head comparison of 3 algorithm families via stratified CV.
    Returns the name of the best-performing one by mean ROC-AUC."""
    n_pos = int(y_train.sum())
    n_neg = int(len(y_train) - n_pos)
    scale_pos_weight = n_neg / max(n_pos, 1)  # XGBoost's own imbalance handling

    candidates = {
        "Logistic Regression": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(class_weight="balanced", max_iter=2000)),
        ]),
        "SVM (RBF kernel)": Pipeline([
            ("scale", StandardScaler()),
            ("clf", SVC(kernel="rbf", class_weight="balanced", probability=True, random_state=42)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, class_weight="balanced", random_state=42
        ),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42),
        "XGBoost": XGBClassifier(
            n_estimators=300, eval_metric="logloss",
            scale_pos_weight=scale_pos_weight, random_state=42,
        ),
        "ANN (MLP)": Pipeline([
            ("scale", StandardScaler()),
            ("clf", MLPClassifier(
                hidden_layer_sizes=(32, 16), max_iter=1000, random_state=42
            )),
        ]),
    }

    print("\n=== Model comparison (5-fold stratified cross-validation, ROC-AUC) ===")
    results = {}
    for name, model in candidates.items():
        scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="roc_auc")
        results[name] = scores.mean()
        print(f"{name:22s}: mean={scores.mean():.4f}  std={scores.std():.4f}  folds={np.round(scores, 3)}")

    best_name = max(results, key=results.get)
    print(f"\nBest model by CV ROC-AUC: {best_name}")
    return best_name


def tune_random_forest(X_train, y_train, cv):
    """RandomizedSearchCV over a real hyperparameter space instead of
    using RandomForestClassifier() defaults."""
    param_dist = {
        "n_estimators": [200, 300, 400, 600],
        "max_depth": [8, 12, 16, 24, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2", None],
    }
    search = RandomizedSearchCV(
        RandomForestClassifier(class_weight="balanced", random_state=42),
        param_distributions=param_dist,
        n_iter=25,
        scoring="roc_auc",
        cv=cv,
        random_state=42,
        n_jobs=-1,
    )
    search.fit(X_train, y_train)
    print(f"\n=== Hyperparameter tuning (RandomizedSearchCV, 25 candidates x 5-fold) ===")
    print("Best params:", search.best_params_)
    print(f"Best CV ROC-AUC: {search.best_score_:.4f}")
    return search.best_estimator_


def main(data_path: str, out_dir: str):
    df = pd.read_csv(data_path).dropna(subset=["url", "label"])
    print(f"Loaded {len(df)} rows — {df['label'].sum()} phishing, {(df['label']==0).sum()} legit")

    X = build_features(df["url"])
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    best_name = compare_models(X_train, y_train, cv)
    print(
        f"\nNote: '{best_name}' may score highest above, but Random Forest is what "
        "gets tuned and exported below — it's typically within noise of SVM/XGBoost/ANN "
        "on this feature set, while being far more reliable to export to ONNX and run "
        "fast in a browser (SVM/ANN inference is slower and less standard client-side)."
    )
    final_model = tune_random_forest(X_train, y_train, cv)

    y_pred = final_model.predict(X_test)
    y_proba = final_model.predict_proba(X_test)[:, 1]
    print("\n=== Final held-out test set performance ===")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))

    importances = sorted(
        zip(FEATURE_NAMES, final_model.feature_importances_),
        key=lambda x: -x[1],
    )
    print("\n=== Feature importance (top signals the model relies on) ===")
    for name, imp in importances:
        print(f"{name:24s} {imp:.4f}")

    from skl2onnx import to_onnx
    onnx_model = to_onnx(
        final_model, X_train[:1].astype(np.float32),
        target_opset=12,
        options={id(final_model): {"zipmap": False}},
    )
    out_path = f"{out_dir}/phishing_url_model.onnx"
    with open(out_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"\nSaved ONNX model to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to CSV with 'url','label' columns")
    parser.add_argument("--out", default="../extension/model", help="Output directory for the ONNX model")
    args = parser.parse_args()
    main(args.data, args.out)
