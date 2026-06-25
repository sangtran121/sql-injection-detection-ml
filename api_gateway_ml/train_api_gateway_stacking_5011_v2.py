"""
======================================================================
eParty — API Gateway ML Training 5011
New model: Stacking Ensemble for API Gateway anomaly detection

Goal:
- Keep old 5001 model as baseline single-model detector.
- Train new 5011 Stacking Ensemble for comparison and upgrade.

Binary label:
- normal -> 0
- outlier/bot/attack -> 1 abnormal

Features used by C# / Flask API:
- inter_api_access_duration
- api_access_uniqueness
- sequence_length
- vsession_duration
- num_sessions
- num_users
- num_unique_apis
- request_rate_per_min
- graph_num_nodes
- graph_num_edges
- graph_density
- graph_self_loops
- graph_avg_degree

Stacking base models:
- Random Forest
- ExtraTrees
- LightGBM if installed, otherwise GradientBoosting fallback
- XGBoost if installed

Meta model:
- Logistic Regression

Evaluation:
- accuracy, precision, recall, F1-score
- confusion matrix
- false positive rate
- false negative rate
- average inference time
======================================================================
"""

import json
import os
import time
import warnings
from typing import Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

DATA_DIR_CANDIDATES = ["data", "."]
MODEL_DIR = "models"
RANDOM_STATE = 42

os.makedirs(MODEL_DIR, exist_ok=True)

# Feature names used by the new 5011 API and C# payload.
FEATURE_COLS = [
    "inter_api_access_duration",
    "api_access_uniqueness",
    "sequence_length",
    "vsession_duration",
    "num_sessions",
    "num_users",
    "num_unique_apis",
    "request_rate_per_min",
    "graph_num_nodes",
    "graph_num_edges",
    "graph_density",
    "graph_self_loops",
    "graph_avg_degree",
]

# Possible original names in the old dataset/training v6.
COLUMN_ALIASES = {
    "inter_api_access_duration": ["inter_api_access_duration", "inter_api_access_duration(sec)"],
    "api_access_uniqueness": ["api_access_uniqueness"],
    "sequence_length": ["sequence_length", "sequence_length(count)"],
    "vsession_duration": ["vsession_duration", "vsession_duration(min)"],
    "num_sessions": ["num_sessions"],
    "num_users": ["num_users"],
    "num_unique_apis": ["num_unique_apis"],
    "request_rate_per_min": ["request_rate_per_min"],
    "graph_num_nodes": ["graph_num_nodes"],
    "graph_num_edges": ["graph_num_edges"],
    "graph_density": ["graph_density"],
    "graph_self_loops": ["graph_self_loops"],
    "graph_avg_degree": ["graph_avg_degree"],
}

LABEL_NAMES = ["normal", "abnormal"]


def find_existing_file(filename: str) -> str:
    for base in DATA_DIR_CANDIDATES:
        path = os.path.join(base, filename)
        if os.path.exists(path):
            return path
    return ""


def normalize_id_col(df: pd.DataFrame) -> pd.DataFrame:
    for col in ["_id", "id", "session_id", "sessionId"]:
        if col in df.columns:
            return df.rename(columns={col: "_id"})
    df = df.copy()
    df["_id"] = df.index.astype(str)
    return df


def find_label_col(df: pd.DataFrame) -> str:
    for col in ["label", "classification", "behavior_type", "type"]:
        if col in df.columns:
            return col
    raise RuntimeError("Không tìm thấy cột label/classification/behavior_type/type")


def load_csv(path: str) -> pd.DataFrame:
    print(f"🔄 Load CSV: {path}")
    df = pd.read_csv(path)
    df = normalize_id_col(df)

    label_col = find_label_col(df)
    df = df.rename(columns={label_col: "label_text"})

    df["_id"] = df["_id"].astype(str)
    df["label_text"] = df["label_text"].astype(str).str.lower().str.strip()

    return df


def extract_graph(path: str) -> pd.DataFrame:
    if not path or not os.path.exists(path):
        return pd.DataFrame()

    print(f"🔄 Load graph: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []

    for idx, item in enumerate(data):
        sid = str(item.get("_id") or item.get("id") or item.get("session_id") or idx)
        edges = item.get("call_graph", []) or item.get("edges", []) or []

        nodes = set()
        self_loops = 0

        for edge in edges:
            if not isinstance(edge, dict):
                continue

            fr = str(edge.get("fromId") or edge.get("from") or edge.get("source") or "")
            to = str(edge.get("toId") or edge.get("to") or edge.get("target") or "")

            if fr:
                nodes.add(fr)
            if to:
                nodes.add(to)
            if fr and to and fr == to:
                self_loops += 1

        node_count = len(nodes)
        edge_count = len(edges)
        density = 0.0 if node_count <= 1 else edge_count / (node_count * (node_count - 1))
        avg_degree = 0.0 if node_count == 0 else (2 * edge_count / node_count)

        rows.append({
            "_id": sid,
            "graph_num_nodes": node_count,
            "graph_num_edges": edge_count,
            "graph_density": density,
            "graph_self_loops": self_loops,
            "graph_avg_degree": avg_degree,
        })

    return pd.DataFrame(rows)


def load_data() -> pd.DataFrame:
    csv_files = [
        find_existing_file("supervised_dataset.csv"),
        find_existing_file("remaining_behavior_ext.csv"),
    ]
    csv_files = [p for p in csv_files if p]

    if not csv_files:
        raise RuntimeError("Không tìm thấy supervised_dataset.csv hoặc remaining_behavior_ext.csv trong ./data hoặc thư mục hiện tại")

    csv_frames = [load_csv(path) for path in csv_files]
    df = pd.concat(csv_frames, ignore_index=True)

    df = df[df["label_text"].isin(["normal", "outlier", "bot", "attack"])].copy()

    print(f"✅ Behavior rows before dedup: {df.shape}")
    print("Label distribution:")
    print(df["label_text"].value_counts())

    graph_files = [
        find_existing_file("supervised_call_graphs.json"),
        find_existing_file("remaining_call_graphs.json"),
    ]
    graph_frames = [extract_graph(path) for path in graph_files if path]
    graph_frames = [g for g in graph_frames if not g.empty]

    if graph_frames:
        graph_df = pd.concat(graph_frames, ignore_index=True)
        graph_df["_id"] = graph_df["_id"].astype(str)

        before_graph = len(graph_df)
        graph_df = graph_df.drop_duplicates("_id", keep="first")
        print(f"ℹ️ Dedup graph _id: {before_graph} -> {len(graph_df)}")

        before_merge = len(df)
        df = df.drop_duplicates("_id", keep="first")
        print(f"ℹ️ Dedup behavior _id: {before_merge} -> {len(df)}")

        df = df.merge(graph_df, on="_id", how="left")
    else:
        before = len(df)
        df = df.drop_duplicates("_id", keep="first")
        print(f"ℹ️ Dedup behavior _id: {before} -> {len(df)}")
        print("⚠️ Không tìm thấy graph JSON, graph features sẽ fill 0")

    return df


def get_first_existing_numeric(df: pd.DataFrame, aliases: List[str], default: float = 0.0) -> pd.Series:
    for col in aliases:
        if col in df.columns:
            return pd.to_numeric(df[col], errors="coerce").fillna(default)
    return pd.Series(default, index=df.index, dtype="float64")


def build_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    print("\n📌 Features dùng cho C# 5011:")

    X = pd.DataFrame(index=df.index)

    for feature in FEATURE_COLS:
        if feature == "request_rate_per_min":
            continue

        X[feature] = get_first_existing_numeric(df, COLUMN_ALIASES[feature], 0.0)
        print(f" - {feature}")

    if any(col in df.columns for col in COLUMN_ALIASES["request_rate_per_min"]):
        X["request_rate_per_min"] = get_first_existing_numeric(df, COLUMN_ALIASES["request_rate_per_min"], 0.0)
    else:
        duration = X["vsession_duration"].replace(0, np.nan)
        X["request_rate_per_min"] = (X["sequence_length"] / duration).replace([np.inf, -np.inf], 0).fillna(0)

    # Ensure exact order.
    X = X[FEATURE_COLS]
    X = X.replace([np.inf, -np.inf], 0).fillna(0)

    y = np.where(df["label_text"] == "normal", 0, 1)
    y = pd.Series(y, index=df.index, name="y")

    print("\nBinary label:")
    print(y.value_counts().rename(index={0: "normal", 1: "abnormal"}))

    print("\nFeature statistics:")
    print(X.describe().round(3).to_string())

    return X, y


def make_base_estimators() -> List[Tuple[str, object]]:
    estimators: List[Tuple[str, object]] = []

    estimators.append((
        "random_forest",
        RandomForestClassifier(
            n_estimators=450,
            max_depth=None,
            min_samples_leaf=2,
            class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    ))

    estimators.append((
        "extra_trees",
        ExtraTreesClassifier(
            n_estimators=600,
            max_depth=None,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
    ))

    try:
        from lightgbm import LGBMClassifier

        estimators.append((
            "lightgbm",
            LGBMClassifier(
                n_estimators=450,
                learning_rate=0.04,
                num_leaves=31,
                subsample=0.9,
                colsample_bytree=0.9,
                class_weight="balanced",
                objective="binary",
                random_state=RANDOM_STATE,
                n_jobs=-1,
                verbose=-1,
            )
        ))
        print("✅ Có LightGBM: đã thêm vào Stacking")
    except Exception as exc:
        estimators.append((
            "gradient_boosting_fallback",
            GradientBoostingClassifier(
                n_estimators=300,
                learning_rate=0.045,
                max_depth=3,
                random_state=RANDOM_STATE,
            )
        ))
        print(f"⚠️ Không có LightGBM: dùng GradientBoosting fallback ({exc})")

    try:
        from xgboost import XGBClassifier

        estimators.append((
            "xgboost",
            XGBClassifier(
                n_estimators=500,
                max_depth=5,
                learning_rate=0.035,
                subsample=0.85,
                colsample_bytree=0.85,
                reg_alpha=0.5,
                reg_lambda=1.5,
                objective="binary:logistic",
                eval_metric="logloss",
                random_state=RANDOM_STATE,
                n_jobs=-1,
                verbosity=0,
            )
        ))
        print("✅ Có XGBoost: đã thêm vào Stacking")
    except Exception as exc:
        print(f"⚠️ Không có XGBoost: bỏ qua ({exc})")

    return estimators


def make_stacking_model() -> StackingClassifier:
    base_estimators = make_base_estimators()

    # Pure stacking:
    # - Meta model only receives base-model abnormal probabilities.
    # - Do NOT passthrough raw features here, because unscaled graph/rate features
    #   can dominate LogisticRegression and make meta output inconsistent
    #   with high base-model anomaly scores.
    meta_model = LogisticRegression(
        C=2.0,
        class_weight="balanced",
        max_iter=3000,
        random_state=RANDOM_STATE,
    )

    model = StackingClassifier(
        estimators=base_estimators,
        final_estimator=meta_model,
        stack_method="predict_proba",
        passthrough=False,
        cv=5,
        n_jobs=-1,
    )

    return model


def find_best_threshold(y_true: pd.Series, probs: np.ndarray) -> Tuple[float, Dict[str, float]]:
    best_threshold = 0.5
    best_score = -1.0
    best_metrics: Dict[str, float] = {}

    for threshold in np.arange(0.20, 0.96, 0.01):
        pred = (probs >= threshold).astype(int)
        report = classification_report(
            y_true,
            pred,
            target_names=LABEL_NAMES,
            output_dict=True,
            zero_division=0,
        )

        macro_f1 = f1_score(y_true, pred, average="macro", zero_division=0)
        abnormal_recall = report["abnormal"]["recall"]
        normal_recall = report["normal"]["recall"]
        abnormal_precision = report["abnormal"]["precision"]

        # Balanced score: catch abnormal but avoid false positives.
        score = macro_f1 + 0.30 * abnormal_recall + 0.25 * normal_recall + 0.10 * abnormal_precision

        if score > best_score:
            best_score = score
            best_threshold = float(round(threshold, 2))
            best_metrics = {
                "score": float(score),
                "macro_f1": float(macro_f1),
                "abnormal_recall": float(abnormal_recall),
                "normal_recall": float(normal_recall),
                "abnormal_precision": float(abnormal_precision),
            }

    return best_threshold, best_metrics


def evaluate_threshold(y_true: pd.Series, probs: np.ndarray, threshold: float) -> Dict[str, object]:
    pred = (probs >= threshold).astype(int)
    cm = confusion_matrix(y_true, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_true, pred)),
        "precision": float(precision_score(y_true, pred, zero_division=0)),
        "recall": float(recall_score(y_true, pred, zero_division=0)),
        "f1": float(f1_score(y_true, pred, zero_division=0)),
        "macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, pred, average="weighted", zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn + 1e-9)),
        "false_negative_rate": float(fn / (fn + tp + 1e-9)),
        "confusion_matrix": cm,
        "classification_report_text": classification_report(y_true, pred, target_names=LABEL_NAMES, digits=4, zero_division=0),
    }

    return metrics


def measure_inference_time(model: object, X_test: pd.DataFrame, sample_size: int = 1000) -> float:
    n = min(sample_size, len(X_test))
    if n <= 0:
        return 0.0

    X_sample = X_test.iloc[:n]

    # Warm-up.
    _ = model.predict_proba(X_sample.iloc[: min(5, n)])

    start = time.perf_counter()
    _ = model.predict_proba(X_sample)
    end = time.perf_counter()

    return float(((end - start) / n) * 1000)


def write_report(
    threshold: float,
    threshold_metrics: Dict[str, float],
    test_metrics: Dict[str, object],
    avg_inference_ms: float,
    base_names: List[str],
    train_shape: Tuple[int, int],
    val_shape: Tuple[int, int],
    test_shape: Tuple[int, int],
) -> None:
    report_path = os.path.join(MODEL_DIR, "api_gateway_report_stacking.txt")

    cm = test_metrics["confusion_matrix"]

    lines = []
    lines.append("eParty API Gateway ML — Stacking Ensemble 5011")
    lines.append("=" * 70)
    lines.append(f"Base models: {', '.join(base_names)}")
    lines.append("Meta model: LogisticRegression")
    lines.append("Stacking mode: pure stacking, passthrough=False")
    lines.append(f"Features: {', '.join(FEATURE_COLS)}")
    lines.append(f"Train shape: {train_shape}")
    lines.append(f"Val shape: {val_shape}")
    lines.append(f"Test shape: {test_shape}")
    lines.append("")
    lines.append(f"Best threshold: {threshold}")
    lines.append(f"Threshold selection metrics: {threshold_metrics}")
    lines.append("")
    lines.append("TEST RESULT")
    lines.append(f"Accuracy: {test_metrics['accuracy']:.6f}")
    lines.append(f"Precision: {test_metrics['precision']:.6f}")
    lines.append(f"Recall: {test_metrics['recall']:.6f}")
    lines.append(f"F1: {test_metrics['f1']:.6f}")
    lines.append(f"Macro F1: {test_metrics['macro_f1']:.6f}")
    lines.append(f"Weighted F1: {test_metrics['weighted_f1']:.6f}")
    lines.append(f"False Positive Rate: {test_metrics['false_positive_rate']:.6f}")
    lines.append(f"False Negative Rate: {test_metrics['false_negative_rate']:.6f}")
    lines.append(f"Average inference time per request: {avg_inference_ms:.4f} ms")
    lines.append("")
    lines.append("Confusion matrix [normal, abnormal]:")
    lines.append(str(cm))
    lines.append("")
    lines.append(test_metrics["classification_report_text"])

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def save_artifacts(model: object, threshold: float, base_names: List[str]) -> None:
    joblib.dump(model, os.path.join(MODEL_DIR, "api_gateway_stacking_model.pkl"))
    joblib.dump(FEATURE_COLS, os.path.join(MODEL_DIR, "api_gateway_features_stacking.pkl"))
    joblib.dump(float(threshold), os.path.join(MODEL_DIR, "api_gateway_threshold_stacking.pkl"))
    joblib.dump("stacking_ensemble_5011", os.path.join(MODEL_DIR, "api_gateway_model_type_stacking.pkl"))
    joblib.dump(LABEL_NAMES, os.path.join(MODEL_DIR, "api_gateway_labels_stacking.pkl"))
    joblib.dump(base_names, os.path.join(MODEL_DIR, "api_gateway_base_models_stacking.pkl"))

    print("\n✅ Saved:")
    print(" - models/api_gateway_stacking_model.pkl")
    print(" - models/api_gateway_features_stacking.pkl")
    print(" - models/api_gateway_threshold_stacking.pkl")
    print(" - models/api_gateway_model_type_stacking.pkl")
    print(" - models/api_gateway_labels_stacking.pkl")
    print(" - models/api_gateway_base_models_stacking.pkl")
    print(" - models/api_gateway_report_stacking.txt")


def main() -> None:
    print("\n############################################################")
    print("# eParty API Gateway ML — New Stacking Ensemble 5011")
    print("############################################################\n")

    df = load_data()
    X, y = build_features(df)

    # Split: test is held out. Threshold is selected on validation.
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val,
        y_train_val,
        test_size=0.20,
        stratify=y_train_val,
        random_state=RANDOM_STATE,
    )

    print(f"\nTrain: {X_train.shape} | Val: {X_val.shape} | Test: {X_test.shape}")

    model = make_stacking_model()
    base_names = [name for name, _ in model.estimators]

    print("\n🚀 Training API Gateway Stacking 5011...")
    model.fit(X_train, y_train)

    val_probs = model.predict_proba(X_val)[:, 1]
    threshold, threshold_metrics = find_best_threshold(y_val, val_probs)
    print(f"✅ Best threshold: {threshold}")
    print(f"Threshold metrics: {threshold_metrics}")

    test_probs = model.predict_proba(X_test)[:, 1]
    test_metrics = evaluate_threshold(y_test, test_probs, threshold)
    avg_inference_ms = measure_inference_time(model, X_test)

    print("\n📊 TEST RESULT")
    print(f"Accuracy: {test_metrics['accuracy']:.6f}")
    print(f"Precision: {test_metrics['precision']:.6f}")
    print(f"Recall: {test_metrics['recall']:.6f}")
    print(f"F1: {test_metrics['f1']:.6f}")
    print(f"False Positive Rate: {test_metrics['false_positive_rate']:.6f}")
    print(f"False Negative Rate: {test_metrics['false_negative_rate']:.6f}")
    print(f"Average inference time: {avg_inference_ms:.4f} ms/request")
    print("Confusion matrix [normal, abnormal]:")
    print(test_metrics["confusion_matrix"])
    print(test_metrics["classification_report_text"])

    # Refit production model on train+validation only. Test remains untouched for report.
    print("\n🔁 Refit model on train+val...")
    final_model = make_stacking_model()
    final_model.fit(X_train_val, y_train_val)

    write_report(
        threshold=threshold,
        threshold_metrics=threshold_metrics,
        test_metrics=test_metrics,
        avg_inference_ms=avg_inference_ms,
        base_names=base_names,
        train_shape=X_train.shape,
        val_shape=X_val.shape,
        test_shape=X_test.shape,
    )

    save_artifacts(final_model, threshold, base_names)

    print("\n✅ DONE.")
    print("Chạy tiếp:")
    print("python api_gateway_stacking_api_5011_new.py")


if __name__ == "__main__":
    main()
