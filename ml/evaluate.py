"""
SafeSurf Pro - ML Inference Evaluator (CLI Test Tool)
Evaluates any URL or feature vector using the trained models.
"""

import argparse
import json
import sys
from pathlib import Path

# Add ml directory to sys.path so features can be imported regardless of cwd
ML_DIR = Path(__file__).resolve().parent
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from features import extract_features, FEATURE_NAMES


def evaluate_single_url(url: str, meta: dict = None):
    features = extract_features(url, meta or {})
    print(f"\n=======================================================")
    print(f"URL: {url}")
    print(f"=======================================================")

    # Try Joblib first if installed
    try:
        import joblib
        model = joblib.load("ml/phishing_model.joblib")
        pred = model.predict([features])[0]
        probs = model.predict_proba([features])[0]
        phish_prob = probs[1]
    except Exception as e:
        model_file = ML_DIR.parent / "models" / "phishing_model.json"
        with open(model_file, "r") as f:
            model_json = json.load(f)
        # Evaluate JSON model
        probs = []
        for tree in model_json["trees"]:
            curr = tree
            while curr["type"] == "split":
                val = features[curr["feature_index"]]
                if val <= curr["threshold"]:
                    curr = curr["left"]
                else:
                    curr = curr["right"]
            probs.append(curr.get("probability", 0.0))
        phish_prob = sum(probs) / len(probs)
        pred = 1 if phish_prob >= 0.5 else 0

    print(f"Verdict:              {'MALICIOUS / PHISHING' if pred == 1 else 'LEGITIMATE / SAFE'}")
    print(f"Phishing Probability: {phish_prob * 100:.2f}%")
    print(f"\nTop Extracted Features:")
    for name, val in zip(FEATURE_NAMES, features):
        if val != 0:
            print(f"  - {name:<25}: {val}")
    print(f"=======================================================\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate a URL with SafeSurf Pro ML")
    parser.add_argument("url", nargs="?", default="http://paypa1-security-verify.xyz/login.php", help="URL to evaluate")
    args = parser.parse_args()
    evaluate_single_url(args.url)
