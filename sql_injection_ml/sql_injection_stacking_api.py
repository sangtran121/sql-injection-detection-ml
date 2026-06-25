from flask import Flask, request, jsonify
import joblib
import re
import os
import time
from urllib.parse import unquote

app = Flask(__name__)

MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "sql_injection_stacking_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer_stacking.pkl")

THRESHOLD = 0.56

print("Loading SQL Injection Stacking model...")
model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
print("Loaded model successfully.")


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


def get_base_model_scores(vector):
    """
    Lấy probability của từng base model trong StackingClassifier.
    Chỉ dùng để hiển thị/giải thích, không dùng để quyết định cuối cùng.
    """
    scores = {}

    if not hasattr(model, "named_estimators_"):
        return scores

    for name, estimator in model.named_estimators_.items():
        try:
            if hasattr(estimator, "predict_proba"):
                prob = float(estimator.predict_proba(vector)[0][1])
                scores[name] = round(prob, 4)
            else:
                scores[name] = None
        except Exception as e:
            scores[name] = None

    return scores


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model": "sql_injection_stacking_ensemble_ml_only",
        "port": 5010,
        "base_models": [
            "logistic_regression",
            "linear_svm",
            "xgboost"
        ],
        "meta_model": "Logistic Regression"
    })


@app.route("/predict", methods=["POST"])
def predict():
    start = time.time()

    try:
        data = request.get_json()

        if not data or "query" not in data:
            return jsonify({
                "error": "Missing 'query' field",
                "decision_source": "stacking_primary_ml_only"
            }), 400

        query = data["query"]
        cleaned = clean_sql_query(query)

        vector = vectorizer.transform([cleaned])

        # Điểm từng model con
        base_model_scores = get_base_model_scores(vector)

        # Điểm cuối cùng của Stacking Ensemble
        raw_prob = float(model.predict_proba(vector)[0][1])
        final_prob = raw_prob
        is_sqli = final_prob >= THRESHOLD

        elapsed_ms = round((time.time() - start) * 1000, 2)

        return jsonify({
            "is_sql_injection": bool(is_sqli),
            "probability": round(final_prob, 4),
            "raw_probability": round(raw_prob, 4),
            "threshold": THRESHOLD,
            "status": "blocked" if is_sqli else "allowed",
            "model": "Stacking Ensemble",
            "decision_source": "stacking_primary_ml_only",
            "response_time_ms": elapsed_ms,

            # THÊM PHẦN NÀY ĐỂ VIEW HIỂN THỊ CHI TIẾT
            "base_model_scores": base_model_scores,
            "meta_model": "Logistic Regression"
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "decision_source": "stacking_primary_error"
        }), 500


if __name__ == "__main__":
    print("SQL Injection Stacking API đang chạy tại http://localhost:5010")
    app.run(host="0.0.0.0", port=5010, debug=False)