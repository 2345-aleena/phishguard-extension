"""
Exports a trained sklearn RandomForestClassifier into plain JSON:
one entry per tree, each node storing its split feature/threshold or
leaf class-probability. This is then evaluated in the browser with a
small hand-written JS walker (see extension/src/forest-model.js) --
no ONNX, no WASM, no dynamic imports. Same trained model, simpler
and far more reliable runtime for a browser extension.

Usage:
    python export_forest_json.py --data ../dataset/phishing_urls_combined.csv
"""

import argparse
import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, RandomizedSearchCV

from train_model import build_features, FEATURE_NAMES  # reuse the same feature extraction


def tree_to_dict(tree, node_id=0):
    """Recursively converts an sklearn tree_ structure into plain JSON.
    Uses short keys (l/f/t/L/R/p) since this gets repeated across
    hundreds of trees and thousands of nodes -- shaves the file size
    down substantially vs. descriptive key names.
    """
    if tree.children_left[node_id] == tree.children_right[node_id]:  # leaf
        counts = tree.value[node_id][0]
        prob_phishing = counts[1] / counts.sum()
        return {"l": 1, "p": round(float(prob_phishing), 4)}

    return {
        "l": 0,
        "f": int(tree.feature[node_id]),
        "t": round(float(tree.threshold[node_id]), 4),
        "L": tree_to_dict(tree, tree.children_left[node_id]),
        "R": tree_to_dict(tree, tree.children_right[node_id]),
    }


def main(data_path: str, out_path: str):
    import pandas as pd
    df = pd.read_csv(data_path).dropna(subset=["url", "label"])
    X = build_features(df["url"])
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    param_dist = {
        "n_estimators": [200, 300, 400, 600],
        "max_depth": [8, 12, 16, 24, None],
        "min_samples_split": [2, 5, 10],
        "min_samples_leaf": [1, 2, 4],
        "max_features": ["sqrt", "log2", None],
    }
    search = RandomizedSearchCV(
        RandomForestClassifier(class_weight="balanced", random_state=42),
        param_distributions=param_dist, n_iter=25, scoring="roc_auc",
        cv=cv, random_state=42, n_jobs=-1,
    )
    search.fit(X_train, y_train)
    print("Best params from search:", search.best_params_)
    print("CV ROC-AUC (best-scoring config):", search.best_score_)

    # For actual deployment, use a deliberately capped forest size --
    # the search's top config (400 trees, depth 24) is marginally better
    # on paper but produces a multi-MB JSON tree dump that's overkill for
    # a browser extension. This still uses the tuned min_samples_leaf/
    # max_features found above, just with bounded size for a practical
    # download footprint.
    best = search.best_params_
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=min(best.get("max_depth") or 14, 14),
        min_samples_split=best["min_samples_split"],
        min_samples_leaf=best["min_samples_leaf"],
        max_features=best["max_features"],
        class_weight="balanced",
        random_state=42,
    )
    model.fit(X_train, y_train)

    from sklearn.metrics import roc_auc_score, classification_report
    y_proba = model.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, model.predict(X_test), target_names=["legit", "phishing"]))
    print("Held-out ROC-AUC:", roc_auc_score(y_test, y_proba))

    forest_json = {
        "featureNames": FEATURE_NAMES,
        "nTrees": len(model.estimators_),
        "trees": [tree_to_dict(est.tree_) for est in model.estimators_],
    }

    with open(out_path, "w") as f:
        json.dump(forest_json, f)

    import os
    size_kb = os.path.getsize(out_path) / 1024
    print(f"\nSaved {len(model.estimators_)}-tree forest as JSON to {out_path} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--out", default="../extension/model/forest_model.json")
    args = parser.parse_args()
    main(args.data, args.out)
