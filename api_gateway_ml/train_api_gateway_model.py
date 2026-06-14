"""
======================================================================
 eParty — API Gateway ML Training v6
 Binary model: normal vs abnormal

Ý tưởng:
- normal  -> 0
- outlier/bot/attack -> 1
- Model chỉ học: bình thường hay bất thường
- Action block/challenge sẽ để Flask rule xử lý
======================================================================
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
import warnings

warnings.filterwarnings(
    "ignore",
    message=".*sklearn.utils.parallel.delayed.*",
    category=UserWarning
)


DATA_DIR = "data"
MODEL_DIR = "models"
RANDOM_STATE = 42

os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLS = [
    "inter_api_access_duration(sec)",
    "api_access_uniqueness",
    "sequence_length(count)",
    "vsession_duration(min)",
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

LABEL_NAMES = ["normal", "abnormal"]


def normalize_id_col(df):
    for c in ["_id", "id", "session_id", "sessionId"]:
        if c in df.columns:
            return df.rename(columns={c: "_id"})
    df["_id"] = df.index.astype(str)
    return df


def find_label_col(df):
    for c in ["label", "classification", "behavior_type", "type"]:
        if c in df.columns:
            return c
    raise Exception("Không tìm thấy cột label/classification/behavior_type")


def load_csv(path):
    df = pd.read_csv(path)
    df = normalize_id_col(df)

    label_col = find_label_col(df)
    df = df.rename(columns={label_col: "label"})

    df["_id"] = df["_id"].astype(str)
    df["label"] = df["label"].astype(str).str.lower().str.strip()

    return df


def extract_graph(path):
    if not os.path.exists(path):
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rows = []

    for item in data:
        sid = str(item.get("_id", ""))
        edges = item.get("call_graph", []) or []

        nodes = set()
        self_loops = 0

        for e in edges:
            fr = str(e.get("fromId", ""))
            to = str(e.get("toId", ""))

            if fr:
                nodes.add(fr)
            if to:
                nodes.add(to)
            if fr and to and fr == to:
                self_loops += 1

        node_count = len(nodes)
        edge_count = len(edges)

        density = 0 if node_count <= 1 else edge_count / (node_count * (node_count - 1))
        avg_degree = 0 if node_count == 0 else (2 * edge_count / node_count)

        rows.append({
            "_id": sid,
            "graph_num_nodes": node_count,
            "graph_num_edges": edge_count,
            "graph_density": density,
            "graph_self_loops": self_loops,
            "graph_avg_degree": avg_degree,
        })

    return pd.DataFrame(rows)


def load_data():
    print("\n================ LOAD DATA ================")

    csv_frames = []

    for path in [
        os.path.join(DATA_DIR, "supervised_dataset.csv"),
        os.path.join(DATA_DIR, "remaining_behavior_ext.csv"),
    ]:
        if os.path.exists(path):
            df_part = load_csv(path)
            csv_frames.append(df_part)
            print(f"✅ CSV {path}: {len(df_part):,}")

    if not csv_frames:
        raise Exception("Không tìm thấy file CSV trong thư mục data/")

    df = pd.concat(csv_frames, ignore_index=True)

    df = df[df["label"].isin(["normal", "outlier", "bot", "attack"])].copy()

    print("\nLabel gốc:")
    print(df["label"].value_counts())

    before = len(df)
    df = df.drop_duplicates("_id", keep="first")
    print(f"\n🧹 Dedup CSV: {before:,} → {len(df):,}")

    graph_frames = []

    for path in [
        os.path.join(DATA_DIR, "supervised_call_graphs.json"),
        os.path.join(DATA_DIR, "remaining_call_graphs.json"),
    ]:
        g = extract_graph(path)
        if not g.empty:
            graph_frames.append(g)
            print(f"✅ GRAPH {path}: {len(g):,}")

    graph_df = pd.concat(graph_frames, ignore_index=True)
    graph_df["_id"] = graph_df["_id"].astype(str)

    before_g = len(graph_df)
    graph_df = graph_df.drop_duplicates("_id", keep="first")
    print(f"🧹 Dedup GRAPH: {before_g:,} → {len(graph_df):,}")

    before_merge = len(df)
    df = df.merge(graph_df, on="_id", how="left")
    print(f"🔗 Merge: {before_merge:,} → {len(df):,}")

    return df


def build_features(df):
    print("\n================ BUILD FEATURES ================")

    required_cols = [
        "inter_api_access_duration(sec)",
        "api_access_uniqueness",
        "sequence_length(count)",
        "vsession_duration(min)",
        "num_sessions",
        "num_users",
        "num_unique_apis",
        "graph_num_nodes",
        "graph_num_edges",
        "graph_density",
        "graph_self_loops",
        "graph_avg_degree",
    ]

    for c in required_cols:
        if c not in df.columns:
            print(f"⚠️ Thiếu cột {c}, fill 0")
            df[c] = 0
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    df["request_rate_per_min"] = np.where(
        df["vsession_duration(min)"] < 0.1,
        0,
        df["sequence_length(count)"] / df["vsession_duration(min)"].replace(0, np.nan)
    )

    df["request_rate_per_min"] = (
        df["request_rate_per_min"]
        .replace([np.inf, -np.inf], 0)
        .fillna(0)
    )

    # Binary label
    df["y"] = np.where(df["label"] == "normal", 0, 1)

    print("\nBinary label:")
    print(df["y"].value_counts().rename(index={0: "normal", 1: "abnormal"}))

    print("\nFeature statistics:")
    print(df[FEATURE_COLS].describe().round(3).to_string())

    X = df[FEATURE_COLS].copy()
    y = df["y"].copy()

    return X, y


def make_models():
    return {
        "xgboost_binary": XGBClassifier(
            n_estimators=700,
            max_depth=5,
            learning_rate=0.035,
            subsample=0.85,
            colsample_bytree=0.85,
            reg_alpha=0.5,
            reg_lambda=1.5,
            objective="binary:logistic",
            eval_metric="logloss",
            n_jobs=-1,
            random_state=RANDOM_STATE,
            verbosity=0,
        ),

        "random_forest_binary": RandomForestClassifier(
            n_estimators=700,
            max_depth=None,
            min_samples_leaf=2,
            class_weight={
                0: 1.0,
                1: 1.2,
            },
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),

        "extra_trees_binary": ExtraTreesClassifier(
            n_estimators=900,
            max_depth=None,
            min_samples_leaf=1,
            class_weight={
                0: 1.0,
                1: 1.2,
            },
            n_jobs=-1,
            random_state=RANDOM_STATE,
        ),

        "gradient_boosting_binary": GradientBoostingClassifier(
            n_estimators=400,
            learning_rate=0.04,
            max_depth=4,
            random_state=RANDOM_STATE,
        ),
    }


def get_sample_weight(y):
    return compute_sample_weight(
        class_weight={
            0: 1.0,
            1: 1.2,
        },
        y=y
    )


def evaluate_all_models(X, y):
    print("\n================ EVALUATE MODELS ================")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        stratify=y,
        random_state=RANDOM_STATE
    )

    results = []

    for name, model in make_models().items():
        print(f"\n🚀 Training {name}...")

        try:
            if "xgboost" in name or "gradient_boosting" in name:
                model.fit(X_train, y_train, sample_weight=get_sample_weight(y_train))
            else:
                model.fit(X_train, y_train)

            pred = model.predict(X_test)

            if hasattr(model, "predict_proba"):
                probs = model.predict_proba(X_test)[:, 1]
            else:
                probs = pred

            acc = accuracy_score(y_test, pred)
            weighted_f1 = f1_score(y_test, pred, average="weighted")
            macro_f1 = f1_score(y_test, pred, average="macro")

            report = classification_report(
                y_test,
                pred,
                target_names=LABEL_NAMES,
                output_dict=True,
                zero_division=0
            )

            normal_recall = report["normal"]["recall"]
            abnormal_recall = report["abnormal"]["recall"]
            abnormal_precision = report["abnormal"]["precision"]

            # Ưu tiên bắt abnormal nhưng vẫn giữ normal recall cao để giảm false positive
            score = (
                macro_f1
                + 0.35 * abnormal_recall
                + 0.25 * normal_recall
                + 0.10 * abnormal_precision
            )

            print(f"Accuracy          : {acc:.4f}")
            print(f"Weighted F1       : {weighted_f1:.4f}")
            print(f"Macro F1          : {macro_f1:.4f}")
            print(f"Normal recall     : {normal_recall:.4f}")
            print(f"Abnormal recall   : {abnormal_recall:.4f}")
            print(f"Abnormal precision: {abnormal_precision:.4f}")
            print(f"SELECT SCORE      : {score:.4f}")

            print("\nReport:")
            print(classification_report(
                y_test,
                pred,
                target_names=LABEL_NAMES,
                zero_division=0
            ))

            results.append({
                "name": name,
                "model": model,
                "score": score,
                "acc": acc,
                "macro_f1": macro_f1,
                "normal_recall": normal_recall,
                "abnormal_recall": abnormal_recall,
                "abnormal_precision": abnormal_precision,
            })

        except Exception as e:
            print(f"❌ {name} lỗi: {e}")

    results = sorted(results, key=lambda r: r["score"], reverse=True)

    print("\n================ BEST MODEL ================")
    best = results[0]

    print(f"🏆 Best model: {best['name']}")
    print(f"Score        : {best['score']:.4f}")
    print(f"Accuracy     : {best['acc']:.4f}")
    print(f"Macro F1     : {best['macro_f1']:.4f}")
    print(f"Normal recall: {best['normal_recall']:.4f}")
    print(f"Abn recall   : {best['abnormal_recall']:.4f}")

    return best["name"]


def train_final_model(best_name, X, y):
    print(f"\n================ FINAL TRAIN 100%: {best_name} ================")

    model = make_models()[best_name]

    if "xgboost" in best_name or "gradient_boosting" in best_name:
        model.fit(X, y, sample_weight=get_sample_weight(y))
    else:
        model.fit(X, y)

    print(f"✅ Final model trained on {len(X):,} rows")

    return model


def stress_test(model):
    print("\n================ EXTENDED STRESS TEST ================")

    cases = [
        # =====================================================
        # NORMAL CASES
        # =====================================================
        ("Normal — user mới vào web", "normal",
         [5, 0.8, 1, 0.05, 1, 1, 1, 0, 1, 0, 0, 0, 0]),

        ("Normal — duyệt menu nhẹ", "normal",
         [8, 0.8, 8, 30, 3, 3, 8, 0.26, 15, 20, 0.095, 1, 2.66]),

        ("Normal — user đặt tiệc bình thường", "normal",
         [12, 0.7, 15, 120, 4, 4, 12, 0.125, 20, 30, 0.079, 2, 3.0]),

        ("Normal — admin xem dashboard", "normal",
         [6, 0.9, 20, 60, 5, 5, 25, 0.33, 30, 45, 0.052, 2, 3.0]),

        ("Normal — nhiều user hợp lệ", "normal",
         [10, 0.85, 40, 300, 20, 18, 35, 0.13, 40, 60, 0.038, 3, 3.0]),

        ("Normal — session dài nhưng nhiều user", "normal",
         [30, 0.75, 80, 5000, 50, 45, 40, 0.016, 45, 70, 0.035, 3, 3.1]),

        ("Normal — request ít, graph nhỏ", "normal",
         [20, 0.9, 5, 100, 2, 2, 5, 0.05, 5, 4, 0.2, 0, 1.6]),

        ("Normal — user quay lại nhiều lần", "normal",
         [15, 0.65, 25, 800, 8, 7, 20, 0.031, 25, 35, 0.058, 1, 2.8]),

        # =====================================================
        # ABNORMAL — OUTLIER-LIKE
        # =====================================================
        ("Abnormal — session cực dài", "abnormal",
         [120, 0.2, 60, 20000, 1, 1, 10, 0.003, 20, 25, 0.065, 2, 2.5]),

        ("Abnormal — duration cực lớn", "abnormal",
         [300, 0.15, 100, 100000, 1, 1, 15, 0.001, 25, 30, 0.05, 2, 2.4]),

        ("Abnormal — uniqueness thấp", "abnormal",
         [5, 0.02, 60, 1000, 1, 1, 3, 0.06, 10, 40, 0.44, 10, 8.0]),

        ("Abnormal — một user gọi nhiều API", "abnormal",
         [2, 0.1, 120, 60, 1, 1, 50, 2.0, 50, 120, 0.049, 8, 4.8]),

        ("Abnormal — graph edge cao", "abnormal",
         [1, 0.3, 200, 100, 1, 1, 30, 2.0, 40, 250, 0.16, 20, 12.5]),

        ("Abnormal — graph density cao", "abnormal",
         [2, 0.2, 70, 50, 1, 1, 15, 1.4, 10, 80, 0.89, 12, 16.0]),

        ("Abnormal — self loop nhiều", "abnormal",
         [3, 0.25, 90, 80, 1, 1, 12, 1.125, 12, 90, 0.68, 50, 15.0]),

        # =====================================================
        # ABNORMAL — BOT-LIKE
        # =====================================================
        ("Bot-like — request đều", "abnormal",
         [1, 0.4, 80, 10, 1, 1, 20, 8, 40, 100, 0.064, 5, 5.0]),

        ("Bot-like — request nhanh", "abnormal",
         [0.5, 0.3, 100, 5, 1, 1, 20, 20, 35, 100, 0.084, 5, 5.7]),

        ("Bot-like — crawl nhiều API", "abnormal",
         [0.8, 0.6, 180, 20, 1, 1, 80, 9.0, 80, 160, 0.025, 6, 4.0]),

        ("Bot-like — graph rộng", "abnormal",
         [1.2, 0.5, 250, 30, 1, 1, 100, 8.3, 120, 300, 0.021, 8, 5.0]),

        ("Bot-like — session ngắn request cao", "abnormal",
         [0.7, 0.4, 60, 2, 1, 1, 30, 30, 30, 90, 0.103, 4, 6.0]),

        # =====================================================
        # ABNORMAL — ATTACK-LIKE
        # =====================================================
        ("Attack-like — flood", "abnormal",
         [0.05, 0.1, 150, 5, 1, 1, 5, 30, 10, 300, 3.3, 80, 60.0]),

        ("Attack-like — brute force login", "abnormal",
         [0.03, 0.05, 120, 2, 1, 1, 3, 60, 6, 200, 6.6, 100, 66.6]),

        ("Attack-like — self-loop cực cao", "abnormal",
         [0.1, 0.05, 200, 3, 1, 1, 4, 66, 8, 400, 7.1, 138, 100.0]),

        ("Attack-like — edge cực cao", "abnormal",
         [0.2, 0.1, 300, 10, 1, 1, 10, 30, 50, 1000, 0.4, 70, 40.0]),

        ("Attack-like — unique API thấp", "abnormal",
         [0.1, 0.01, 80, 4, 1, 1, 1, 20, 5, 160, 8.0, 60, 64.0]),

        ("Attack-like — single user high graph", "abnormal",
         [0.4, 0.1, 250, 20, 1, 1, 5, 12.5, 20, 500, 1.31, 90, 50.0]),

        # =====================================================
        # BORDERLINE CASES
        # =====================================================
        ("Borderline — hơi nhanh nhưng nhiều user", "normal",
         [2, 0.7, 50, 60, 15, 14, 30, 0.83, 30, 55, 0.063, 3, 3.66]),

        ("Borderline — request cao nhưng session dài", "normal",
         [5, 0.75, 120, 2000, 10, 9, 45, 0.06, 45, 90, 0.045, 4, 4.0]),

        ("Borderline — graph hơi dày", "abnormal",
         [3, 0.3, 80, 100, 1, 1, 15, 0.8, 15, 100, 0.47, 20, 13.3]),

        ("Borderline — one user nhiều request", "abnormal",
         [2, 0.4, 100, 80, 1, 1, 30, 1.25, 25, 90, 0.15, 10, 7.2]),
    ]

    print(f"\n{'#':<3} {'Case':<45} {'Exp':<9} {'Pred':<9} {'Score':>8}")
    print("-" * 88)

    correct = 0
    false_positive = 0
    false_negative = 0

    for i, (desc, expected, feats) in enumerate(cases, 1):
        X_case = pd.DataFrame([feats], columns=FEATURE_COLS)

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_case)[0]
            abnormal_score = float(probs[1])
        else:
            pred_raw = int(model.predict(X_case)[0])
            abnormal_score = float(pred_raw)

        pred = "abnormal" if abnormal_score >= 0.50 else "normal"

        ok = pred == expected

        if ok:
            correct += 1
        else:
            if expected == "normal" and pred == "abnormal":
                false_positive += 1
            elif expected == "abnormal" and pred == "normal":
                false_negative += 1

        print(
            f"{i:<3} {desc:<45} {expected:<9} {pred:<9} "
            f"{abnormal_score:>8.4f} {'✅' if ok else '❌'}"
        )

    total = len(cases)
    acc = correct / total

    print("\n================ STRESS TEST SUMMARY ================")
    print(f"Total          : {total}")
    print(f"Correct        : {correct}")
    print(f"Accuracy       : {acc:.2%}")
    print(f"False positive : {false_positive}  normal bị báo abnormal")
    print(f"False negative : {false_negative}  abnormal bị lọt qua normal")


def save_model(model, best_name):
    print("\n================ SAVE MODEL ================")

    joblib.dump(model, os.path.join(MODEL_DIR, "api_gateway_model.pkl"))
    joblib.dump(FEATURE_COLS, os.path.join(MODEL_DIR, "api_gateway_features.pkl"))
    joblib.dump(LABEL_NAMES, os.path.join(MODEL_DIR, "api_gateway_labels.pkl"))
    joblib.dump(best_name, os.path.join(MODEL_DIR, "api_gateway_model_type.pkl"))

    print("✅ Saved:")
    print("models/api_gateway_model.pkl")
    print("models/api_gateway_features.pkl")
    print("models/api_gateway_labels.pkl")
    print("models/api_gateway_model_type.pkl")


def main():
    print("\n############################################################")
    print("# eParty API Gateway ML — v6 Binary Normal vs Abnormal")
    print("############################################################")

    df = load_data()
    X, y = build_features(df)

    best_name = evaluate_all_models(X, y)

    final_model = train_final_model(best_name, X, y)

    stress_test(final_model)

    save_model(final_model, best_name)

    print("\n✅ DONE.")
    print("Chạy tiếp:")
    print("python api_gateway_detector.py")


if __name__ == "__main__":
    main()