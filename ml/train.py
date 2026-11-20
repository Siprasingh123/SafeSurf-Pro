"""
SafeSurf Pro - Machine Learning Training & Evaluation Pipeline
Trains Random Forest and Decision Tree classifiers for phishing detection.
Evaluates accuracy, precision, recall, F1, and confusion matrix.
Exports the trained model to JSON for real-time in-browser inference.
"""

import json
import os
import shutil
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from features import FEATURE_NAMES
from generate_dataset import generate_dataset


def export_decision_tree_to_dict(tree, feature_names):
    """Recursively converts a scikit-learn tree object to a JSON-serializable dictionary."""
    tree_ = tree.tree_

    def recurse(node):
        if tree_.children_left[node] == tree_.children_right[node]:  # Leaf node
            val = tree_.value[node][0]
            total = float(np.sum(val))
            prob_phishing = float(val[1] / total) if total > 0 else 0.0
            prediction = 1 if prob_phishing >= 0.5 else 0
            return {
                "type": "leaf",
                "prediction": prediction,
                "probability": round(prob_phishing, 4),
                "samples": int(tree_.n_node_samples[node])
            }
        else:
            feature_idx = int(tree_.feature[node])
            feature_name = feature_names[feature_idx]
            threshold = float(tree_.threshold[node])
            left_child = recurse(tree_.children_left[node])
            right_child = recurse(tree_.children_right[node])
            return {
                "type": "split",
                "feature_index": feature_idx,
                "feature_name": feature_name,
                "threshold": round(threshold, 4),
                "left": left_child,   # <= threshold
                "right": right_child  # > threshold
            }

    return recurse(0)


def export_random_forest_to_dict(rf_model, feature_names, max_trees=5):
    """Exports an ensemble of trees to JSON structure for ultra-fast JS inference."""
    trees = []
    # Use top trees from forest to keep extension JSON lightweight and fast
    trees_to_export = rf_model.estimators_[:max_trees]
    for estimator in trees_to_export:
        trees.append(export_decision_tree_to_dict(estimator, feature_names))

    # Calculate feature importances
    importances = {
        name: round(float(imp), 4)
        for name, imp in zip(feature_names, rf_model.feature_importances_)
    }

    return {
        "model_type": "RandomForestEnsemble",
        "feature_names": feature_names,
        "n_trees": len(trees),
        "feature_importances": importances,
        "trees": trees
    }


def train_and_evaluate(csv_path="ml/dataset.csv"):
    if not os.path.exists(csv_path):
        print("[Train] Generating dataset first...")
        generate_dataset(csv_path)

    # Load dataset
    data = np.genfromtxt(csv_path, delimiter=",", skip_header=1)
    X = data[:, :-1]
    y = data[:, -1]

    # 80/20 stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[Train] Training samples: {X_train.shape[0]} | Testing samples: {X_test.shape[0]}")

    # 1. Decision Tree Model
    dt_model = DecisionTreeClassifier(max_depth=8, min_samples_split=6, random_state=42)
    dt_model.fit(X_train, y_train)
    dt_preds = dt_model.predict(X_test)

    dt_metrics = {
        "accuracy": round(float(accuracy_score(y_test, dt_preds)), 4),
        "precision": round(float(precision_score(y_test, dt_preds)), 4),
        "recall": round(float(recall_score(y_test, dt_preds)), 4),
        "f1_score": round(float(f1_score(y_test, dt_preds)), 4),
        "confusion_matrix": confusion_matrix(y_test, dt_preds).tolist()
    }

    # 2. Random Forest Model
    rf_model = RandomForestClassifier(n_estimators=50, max_depth=10, min_samples_split=4, random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    rf_cm = confusion_matrix(y_test, rf_preds)
    rf_metrics = {
        "accuracy": round(float(accuracy_score(y_test, rf_preds)), 4),
        "precision": round(float(precision_score(y_test, rf_preds)), 4),
        "recall": round(float(recall_score(y_test, rf_preds)), 4),
        "f1_score": round(float(f1_score(y_test, rf_preds)), 4),
        "confusion_matrix": rf_cm.tolist()
    }

    report = {
        "evaluation_summary": {
            "total_samples": int(len(y)),
            "train_samples": int(len(y_train)),
            "test_samples": int(len(y_test)),
            "features_count": len(FEATURE_NAMES)
        },
        "decision_tree": dt_metrics,
        "random_forest": rf_metrics,
        "feature_importances": {
            name: round(float(imp), 4)
            for name, imp in sorted(
                zip(FEATURE_NAMES, rf_model.feature_importances_),
                key=lambda x: x[1],
                reverse=True
            )
        }
    }

    # Save reports
    with open("ml/evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    readable_report = f"""================================================================================
SAFESURF PRO - MACHINE LEARNING MODEL EVALUATION REPORT
================================================================================
Dataset Split: 80% Train ({len(y_train)} samples), 20% Test ({len(y_test)} samples)
Feature Space: {len(FEATURE_NAMES)} Security Indicators

1. DECISION TREE CLASSIFIER:
--------------------------------------------------------------------------------
Accuracy:          {dt_metrics['accuracy'] * 100:.2f}%
Precision:         {dt_metrics['precision'] * 100:.2f}%
Recall:            {dt_metrics['recall'] * 100:.2f}%
F1-Score:          {dt_metrics['f1_score'] * 100:.2f}%
Confusion Matrix:
  [True Neg (Benign):  {dt_metrics['confusion_matrix'][0][0]} | False Pos: {dt_metrics['confusion_matrix'][0][1]}]
  [False Neg:          {dt_metrics['confusion_matrix'][1][0]} | True Pos (Phish): {dt_metrics['confusion_matrix'][1][1]}]

2. RANDOM FOREST ENSEMBLE (Selected Production Classifier):
--------------------------------------------------------------------------------
Accuracy:          {rf_metrics['accuracy'] * 100:.2f}%
Precision:         {rf_metrics['precision'] * 100:.2f}%
Recall:            {rf_metrics['recall'] * 100:.2f}%
F1-Score:          {rf_metrics['f1_score'] * 100:.2f}%
Confusion Matrix:
  [True Neg (Benign):  {rf_cm[0][0]} | False Pos: {rf_cm[0][1]}]
  [False Neg:          {rf_cm[1][0]} | True Pos (Phish): {rf_cm[1][1]}]

3. TOP PREDICTIVE FEATURE IMPORTANCES:
--------------------------------------------------------------------------------
"""
    for fname, fimp in sorted(report["feature_importances"].items(), key=lambda x: x[1], reverse=True)[:10]:
        readable_report += f"  - {fname:<25}: {fimp * 100:.2f}%\n"

    readable_report += "================================================================================\n"

    with open("ml/evaluation_report.txt", "w", encoding="utf-8") as f:
        f.write(readable_report)

    print(readable_report)

    # Save Joblib model
    joblib.dump(rf_model, "ml/phishing_model.joblib")

    # Export to JSON for Chrome Extension runtime
    model_json = export_random_forest_to_dict(rf_model, FEATURE_NAMES, max_trees=5)
    os.makedirs("models", exist_ok=True)
    with open("models/phishing_model.json", "w", encoding="utf-8") as f:
        json.dump(model_json, f, indent=2)

    # Also keep a copy in ml/
    with open("ml/phishing_model.json", "w", encoding="utf-8") as f:
        json.dump(model_json, f, indent=2)

    print(f"[Export] Saved browser-ready model -> models/phishing_model.json")
    return report


if __name__ == "__main__":
    train_and_evaluate()
