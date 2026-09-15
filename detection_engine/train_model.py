"""
Model Training Module — Machine Learning Classifier for IAM Privilege Escalation Risk
Person 2 Module — /detection_engine/train_model.py
"""

import os
import json
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


FEATURE_NAMES = [
    "has_wildcard_action",
    "has_wildcard_resource",
    "passrole_count",
    "create_policy_version_count",
    "assume_role_count",
    "ec2_run_instances_count",
    "is_cross_account",
    "shortest_path_to_admin",
    "downstream_reachable_nodes",
    "in_degree",
    "out_degree",
    "has_condition_constraints",
]


def generate_training_dataset():
    """Generates synthetic and benchmark feature vectors modeled on Rhino Security & AWS CIS benchmarks."""
    X = []
    y = []

    # 1. High-risk PassRole + RunInstances vectors
    for _ in range(40):
        # [wildcard_act, wildcard_res, passrole, create_ver, assume, run_inst, cross_acc, dist_to_admin, blast, in_deg, out_deg, cond]
        X.append([0.0, 1.0, 1.0, 0.0, 0.0, 1.0, 0.0, 2.0, 14.0, 1.0, 3.0, 0.0])
        y.append(1)

    # 2. High-risk CreatePolicyVersion vectors
    for _ in range(40):
        X.append([0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0, 18.0, 1.0, 2.0, 0.0])
        y.append(1)

    # 3. High-risk Cross-Account AssumeRole chain vectors
    for _ in range(40):
        X.append([0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 1.0, 2.0, 15.0, 2.0, 2.0, 0.0])
        y.append(1)

    # 4. Wildcard over-permission vectors
    for _ in range(40):
        X.append([1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 4.0, 8.0, 1.0, 2.0, 0.0])
        y.append(1)

    # 5. SetDefaultPolicyVersion rollback vectors
    for _ in range(30):
        X.append([0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 2.0, 12.0, 1.0, 2.0, 0.0])
        y.append(1)

    # 6. Benign read-only developer / audit profiles (Negative samples)
    for _ in range(60):
        X.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 99.0, 0.0, 2.0, 1.0, 1.0])
        y.append(0)

    # 7. Constrained service roles (Negative samples)
    for _ in range(50):
        X.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 99.0, 1.0, 1.0, 1.0, 1.0])
        y.append(0)

    # 8. Billing & compliance analysts (Negative samples)
    for _ in range(50):
        X.append([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 99.0, 0.0, 1.0, 1.0, 0.0])
        y.append(0)

    # Add small Gaussian noise to simulate real-world variance
    X_arr = np.array(X, dtype=np.float32)
    noise = np.random.normal(0, 0.02, X_arr.shape)
    X_noisy = np.clip(X_arr + noise, 0, None)
    y_arr = np.array(y, dtype=np.int32)

    return X_noisy, y_arr


def train_model(output_dir: str = "detection_engine/models"):
    """Trains the Random Forest and Gradient Boosting models and saves artifacts."""
    os.makedirs(output_dir, exist_ok=True)
    X, y = generate_training_dataset()

    # Split 80/20 train/test
    indices = np.random.permutation(len(X))
    split = int(0.8 * len(X))
    train_idx, test_idx = indices[:split], indices[split:]

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    # Train Random Forest Classifier
    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"Model Training Results:")
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  Precision: {prec * 100:.2f}%")
    print(f"  Recall:    {rec * 100:.2f}%")
    print(f"  F1 Score:  {f1:.4f}")

    # Feature importances
    importances = dict(zip(FEATURE_NAMES, [float(x) for x in rf.feature_importances_]))
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    model_path = os.path.join(output_dir, "iam_risk_classifier.pkl")
    joblib.dump(rf, model_path)

    metadata = {
        "model_type": "RandomForestClassifier",
        "num_estimators": 100,
        "max_depth": 6,
        "metrics": {
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1": float(f1),
        },
        "feature_names": FEATURE_NAMES,
        "feature_importances": sorted_importances,
    }

    meta_path = os.path.join(output_dir, "model_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to {model_path}")
    print(f"Metadata saved to {meta_path}")
    return rf, metadata


if __name__ == "__main__":
    train_model()
