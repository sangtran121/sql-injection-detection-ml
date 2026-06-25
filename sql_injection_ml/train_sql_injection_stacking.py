# ============================================================
# SQL INJECTION DETECTION - STACKING ENSEMBLE
# Dataset giữ nguyên: Modified_SQL_Dataset.csv
# Model mới:
# TF-IDF char n-gram
# + Logistic Regression
# + Linear SVM calibrated
# + XGBoost
# + Meta Logistic Regression
# ============================================================

import os
import re
import time
import joblib
import warnings
import numpy as np
import pandas as pd
from urllib.parse import unquote

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import StackingClassifier
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

DATASET_PATH = "Modified_SQL_Dataset.csv"
MODEL_DIR = "models"

OLD_MODEL_NAME = "sql_injection_xgboost_model.pkl"
NEW_MODEL_NAME = "sql_injection_stacking_model.pkl"
VECTORIZER_NAME = "tfidf_vectorizer_stacking.pkl"
REPORT_NAME = "sql_injection_stacking_report.txt"

RANDOM_STATE = 42
THRESHOLD = 0.56


def clean_sql_query(text):
    text = str(text).lower()

    # Decode URL encoding nhiều lần
    decoded = text
    for _ in range(3):
        temp = unquote(decoded)
        if temp == decoded:
            break
        decoded = temp

    def norm_space(s):
        return re.sub(r"\s+", " ", s).strip()

    # Chuẩn hóa số tiền lớn để tránh model hiểu sai các chuỗi như 50,000,000
    decoded = re.sub(r"\b\d{1,3}(?:[,.]\d{3})+\b", " money_amount ", decoded)
    decoded = re.sub(r"\b\d{5,}\b", " large_number ", decoded)

    original = norm_space(decoded)

    # UNION/**/SELECT -> UNION SELECT
    comment_as_space = re.sub(
        r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/",
        " ",
        decoded
    )
    comment_as_space = norm_space(comment_as_space)

    # UNI/**/ON -> UNION
    comment_removed = re.sub(
        r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/",
        "",
        decoded
    )
    comment_removed = norm_space(comment_removed)

    # Chỉ ghép các phiên bản khác nhau, tránh lặp câu bình thường 3 lần
    variants = []
    for v in [original, comment_as_space, comment_removed]:
        if v and v not in variants:
            variants.append(v)

    combined = " ".join(variants)
    combined = re.sub(r"\s+", " ", combined)

    return combined.strip()


def calculate_false_positive_rate(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)

    # cm format:
    # [[TN, FP],
    #  [FN, TP]]
    if cm.shape != (2, 2):
        return 0.0

    tn, fp, fn, tp = cm.ravel()
    if fp + tn == 0:
        return 0.0

    return fp / (fp + tn)


def evaluate_model(name, model, X_test, y_test):
    start = time.time()
    y_proba = model.predict_proba(X_test)[:, 1]
    inference_time = (time.time() - start) / len(y_test)

    y_pred = (y_proba >= THRESHOLD).astype(int)

    acc = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    fpr = calculate_false_positive_rate(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 80)
    print(f"KẾT QUẢ MODEL: {name}")
    print("=" * 80)
    print(classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix:")
    print(cm)
    print(f"Accuracy:        {acc:.6f}")
    print(f"Precision:       {precision:.6f}")
    print(f"Recall:          {recall:.6f}")
    print(f"F1-score:        {f1:.6f}")
    print(f"False Positive:  {fpr:.6f}")
    print(f"Inference/sample:{inference_time * 1000:.4f} ms")

    return {
        "model": name,
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
        "inference_ms_per_sample": inference_time * 1000,
        "confusion_matrix": cm
    }


def build_models():
    # Model 1: Logistic Regression
    lr = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    )

    # Model 2: Linear SVM + calibration để có predict_proba()
    svm = CalibratedClassifierCV(
        estimator=LinearSVC(
            class_weight="balanced",
            random_state=RANDOM_STATE
        ),
        cv=3
    )

    # Model 3: XGBoost
    xgb = XGBClassifier(
        n_estimators=250,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.8,
        reg_alpha=1.0,
        reg_lambda=1.0,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss"
    )

    # Stacking Ensemble
    stacking = StackingClassifier(
        estimators=[
            ("logistic_regression", lr),
            ("linear_svm", svm),
            ("xgboost", xgb),
        ],
        final_estimator=LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=RANDOM_STATE
        ),
        stack_method="predict_proba",
        cv=5,
        n_jobs=-1,
        passthrough=False
    )

    return lr, svm, xgb, stacking



def stress_test(model, vectorizer):
    print("\n" + "=" * 80)
    print("STRESS TEST SQL INJECTION STACKING")
    print("=" * 80)

    test_cases = [
        # Malicious
        ("admin' OR '1'='1' --", 1),
        ("admin' OR 1=1 --", 1),
        ("UNION SELECT username, password FROM users --", 1),
        ("1; DROP TABLE Events --", 1),
        ("WAITFOR DELAY '0:0:5'--", 1),
        ("pg_sleep(5)--", 1),
        ("SELECT * FROM information_schema.tables", 1),
        ("EXEC xp_cmdshell 'dir'", 1),
        ("CAST((SELECT password FROM users) AS int)", 1),
        ("admin'/**/OR/**/1=1--", 1),

        # Benign gần với project eParty
        ("Tạo tiệc cưới ngoài trời cho 120 khách", 0),
        ("Tôi muốn đặt tiệc sinh nhật cho bé gái 8 tuổi", 0),
        ("Menu gồm gỏi cuốn, cá kho tộ và thịt nướng", 0),
        ("Sự kiện công ty ABC ngày 20/05/2026", 0),
        ("Khách mời khoảng 150 người, có MC và sân khấu", 0),
        ("Tổng chi phí dự kiến là 85000000 VNĐ", 0),

        # Normal SQL nội bộ có thể xuất hiện trong hệ thống
        ("SELECT * FROM Events WHERE EventID = 42", 0),
        ("UPDATE Events SET Status = 'Confirmed' WHERE EventID = 10", 0),
        ("SELECT COUNT(*) FROM Staff WHERE IsActive = 1", 0),
    ]

    correct = 0

    for query, expected in test_cases:
        cleaned = clean_sql_query(query)
        vector = vectorizer.transform([cleaned])
        raw_prob = float(model.predict_proba(vector)[0][1])
        prob = raw_prob
        pred = 1 if prob >= THRESHOLD else 0

        ok = pred == expected
        if ok:
            correct += 1

        print(
            f"{'OK' if ok else 'FAIL'} | "
            f"Expected={expected} | Pred={pred} | "
            f"Raw={raw_prob:.4f} | Final={prob:.4f} | {query}"
        )

    print(f"\nStress test đúng: {correct}/{len(test_cases)} = {correct / len(test_cases) * 100:.2f}%")


def main():
    print("\n============================================================")
    print("SQL INJECTION - TRAIN STACKING ENSEMBLE")
    print("============================================================")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Không tìm thấy dataset: {DATASET_PATH}")

    os.makedirs(MODEL_DIR, exist_ok=True)

    print("\nB1: Load dataset...")
    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset shape: {df.shape}")
    print("Columns:", list(df.columns))

    if "Query" not in df.columns or "Label" not in df.columns:
        raise ValueError("Dataset phải có 2 cột: Query và Label")

    print("\nLabel distribution:")
    print(df["Label"].value_counts())

    df["clean_query"] = df["Query"].apply(clean_sql_query)

    X = df["clean_query"]
    y = df["Label"].astype(int)

    print("\nB2: TF-IDF char n-gram...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 3),
        analyzer="char_wb"
    )

    X_vec = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_vec,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y
    )

    print(f"Train size: {X_train.shape}")
    print(f"Test size:  {X_test.shape}")

    print("\nB3: Build models...")
    lr, svm, xgb, stacking = build_models()

    results = []

    print("\nB4: Train Logistic Regression...")
    lr.fit(X_train, y_train)
    results.append(evaluate_model("Logistic Regression", lr, X_test, y_test))

    print("\nB5: Train Linear SVM calibrated...")
    svm.fit(X_train, y_train)
    results.append(evaluate_model("Linear SVM calibrated", svm, X_test, y_test))

    print("\nB6: Train XGBoost baseline...")
    xgb.fit(X_train, y_train)
    results.append(evaluate_model("XGBoost", xgb, X_test, y_test))

    print("\nB7: Train Stacking Ensemble...")
    stacking.fit(X_train, y_train)
    results.append(evaluate_model("Stacking Ensemble", stacking, X_test, y_test))
    print("\n" + "=" * 80)
    print("KIỂM TRA OVERFITTING - STACKING ENSEMBLE")
    print("=" * 80)

    train_proba = stacking.predict_proba(X_train)[:, 1]
    test_proba = stacking.predict_proba(X_test)[:, 1]

    train_pred = (train_proba >= THRESHOLD).astype(int)
    test_pred = (test_proba >= THRESHOLD).astype(int)

    train_acc = accuracy_score(y_train, train_pred)
    test_acc = accuracy_score(y_test, test_pred)

    train_f1 = f1_score(y_train, train_pred, zero_division=0)
    test_f1 = f1_score(y_test, test_pred, zero_division=0)

    train_recall = recall_score(y_train, train_pred, zero_division=0)
    test_recall = recall_score(y_test, test_pred, zero_division=0)

    print(f"Train Accuracy: {train_acc:.6f}")
    print(f"Test Accuracy:  {test_acc:.6f}")
    print(f"Gap Accuracy:   {train_acc - test_acc:.6f}")

    print(f"Train F1-score: {train_f1:.6f}")
    print(f"Test F1-score:  {test_f1:.6f}")
    print(f"Gap F1-score:   {train_f1 - test_f1:.6f}")

    print(f"Train Recall:   {train_recall:.6f}")
    print(f"Test Recall:    {test_recall:.6f}")
    print(f"Gap Recall:     {train_recall - test_recall:.6f}")

    print("\nB8: So sánh model...")
    comparison = pd.DataFrame(results)
    comparison = comparison.drop(columns=["confusion_matrix"])
    comparison = comparison.sort_values(by=["f1", "recall"], ascending=False)

    print("\nBẢNG SO SÁNH:")
    print(comparison.to_string(index=False))

    print("\nB9: Stress test model Stacking...")
    stress_test(stacking, vectorizer)

    print("\nB10: Save model...")
    joblib.dump(stacking, os.path.join(MODEL_DIR, NEW_MODEL_NAME))
    joblib.dump(vectorizer, os.path.join(MODEL_DIR, VECTORIZER_NAME))

    report_path = os.path.join(MODEL_DIR, REPORT_NAME)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("SQL Injection Stacking Ensemble Report\n")
        f.write("=" * 80 + "\n\n")
        f.write("Dataset: Modified_SQL_Dataset.csv\n")
        f.write("Feature: TF-IDF char_wb n-gram 1-3, max_features=5000\n")
        f.write("Base models: Logistic Regression, Linear SVM calibrated, XGBoost\n")
        f.write("Meta model: Logistic Regression\n")
        f.write(f"Threshold: {THRESHOLD}\n\n")
        f.write(comparison.to_string(index=False))
        f.write("\n\n")
        for r in results:
            f.write("\n" + "=" * 80 + "\n")
            f.write(r["model"] + "\n")
            f.write("=" * 80 + "\n")
            f.write(f"Accuracy: {r['accuracy']:.6f}\n")
            f.write(f"Precision: {r['precision']:.6f}\n")
            f.write(f"Recall: {r['recall']:.6f}\n")
            f.write(f"F1-score: {r['f1']:.6f}\n")
            f.write(f"False Positive Rate: {r['false_positive_rate']:.6f}\n")
            f.write(f"Inference ms/sample: {r['inference_ms_per_sample']:.4f}\n")
            f.write(f"Confusion Matrix:\n{r['confusion_matrix']}\n")

    print("\nĐÃ LƯU:")
    print(f"- {os.path.join(MODEL_DIR, NEW_MODEL_NAME)}")
    print(f"- {os.path.join(MODEL_DIR, VECTORIZER_NAME)}")
    print(f"- {report_path}")

    print("\nHoàn tất. Chạy tiếp:")
    print("python sql_injection_stacking_api.py")


if __name__ == "__main__":
    main()