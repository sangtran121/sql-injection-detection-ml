"""
============================================================
  eParty — API Gateway ML Detector v6
  Binary model: normal vs abnormal

  Endpoint:
    POST http://localhost:5001/predict-api-gateway

  Output:
    {
      "is_abnormal": true,
      "risk_score": 0.9184,
      "attack_score": 0.9184,
      "predicted_label": "abnormal",
      "rule_attack": true,
      "action": "challenge_or_rate_limit",
      "decision_source": "ml_monitor"
    }
============================================================
"""

import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify

app = Flask(__name__)

MODEL_DIR = "models"

# ============================================================
# LOAD MODEL
# ============================================================
print("🚀 Đang load API Gateway ML model v6...")

try:
    model = joblib.load(os.path.join(MODEL_DIR, "api_gateway_model.pkl"))
    feature_cols = joblib.load(os.path.join(MODEL_DIR, "api_gateway_features.pkl"))
    label_names = joblib.load(os.path.join(MODEL_DIR, "api_gateway_labels.pkl"))

    try:
        model_type = joblib.load(os.path.join(MODEL_DIR, "api_gateway_model_type.pkl"))
    except Exception:
        model_type = "unknown"

    MODEL_LOADED = True

    print("✅ Model loaded")
    print(f"   Model type: {model_type}")
    print(f"   Features  : {feature_cols}")
    print(f"   Labels    : {label_names}")

except Exception as e:
    MODEL_LOADED = False
    model = None
    feature_cols = []
    label_names = []
    model_type = "none"

    print(f"❌ Không load được model: {e}")
    print("   Hãy chạy train_api_gateway_model.py trước!")


# ============================================================
# CONFIG
# ============================================================

SAFE_ACTIONS = ["login", "register"]

# ML score thresholds
ML_MONITOR_THRESHOLD = 0.55
ML_CHALLENGE_THRESHOLD = 0.80
ML_HIGH_RISK_THRESHOLD = 0.95

# Rule thresholds
RATE_CHALLENGE_THRESHOLD = 50
RATE_BLOCK_THRESHOLD = 120

INTER_SHORT_THRESHOLD = 0.10
INTER_BLOCK_THRESHOLD = 0.05

SEQ_CHALLENGE_THRESHOLD = 30
SEQ_BLOCK_THRESHOLD = 80

GRAPH_EDGE_CHALLENGE_THRESHOLD = 80
GRAPH_EDGE_BLOCK_THRESHOLD = 250

GRAPH_SELF_LOOP_CHALLENGE_THRESHOLD = 25
GRAPH_SELF_LOOP_BLOCK_THRESHOLD = 80

# Không dùng avg_degree để rate-limit sớm nữa,
# vì refresh cùng 1 URL làm avg_degree tăng rất nhanh.
GRAPH_AVG_DEGREE_CHALLENGE_THRESHOLD = 999
GRAPH_AVG_DEGREE_BLOCK_THRESHOLD = 999


# ============================================================
# HELPERS
# ============================================================

def safe_float(data, key, default=0.0):
    try:
        return float(data.get(key, default))
    except Exception:
        return default


def is_safe_action(action_name: str) -> bool:
    return str(action_name or "").lower() in SAFE_ACTIONS


def fallback_allow(reason="fallback"):
    return jsonify({
        "is_abnormal": False,
        "risk_score": 0,
        "attack_score": 0,
        "predicted_label": "normal",
        "rule_attack": False,
        "action": "allow",
        "decision_source": reason,
    }), 200


# ============================================================
# RULE ENGINE
# ============================================================

def compute_rule_action(raw, action_name: str):
    """
    Rule engine:
    - Login/Register không hard-block
    - Route thường: rule rất mạnh mới block
    - Rule vừa mạnh: challenge/rate-limit
    """

    safe = is_safe_action(action_name)

    request_rate = raw["request_rate_per_min"]
    inter_duration = raw["inter_api_access_duration(sec)"]
    seq_length = raw["sequence_length(count)"]

    graph_edges = raw["graph_num_edges"]
    graph_self_loops = raw["graph_self_loops"]
    graph_avg_degree = raw["graph_avg_degree"]

    flood_challenge = request_rate > RATE_CHALLENGE_THRESHOLD
    flood_block = request_rate > RATE_BLOCK_THRESHOLD

    brute_challenge = (
    inter_duration < INTER_SHORT_THRESHOLD
    and seq_length >= 30
    )

    brute_block = (
        inter_duration < INTER_BLOCK_THRESHOLD
        and seq_length >= 100
    )

    # Graph rule chỉ kích hoạt khi có đủ số request.
    # Tránh trường hợp user mới refresh 7-10 lần đã bị 429.
    graph_challenge = (
        seq_length >= 25
        and (
            graph_edges >= GRAPH_EDGE_CHALLENGE_THRESHOLD
            or graph_self_loops >= GRAPH_SELF_LOOP_CHALLENGE_THRESHOLD
        )
    )

    graph_block = (
        seq_length >= 80
        and (
            graph_edges >= GRAPH_EDGE_BLOCK_THRESHOLD
            or graph_self_loops >= GRAPH_SELF_LOOP_BLOCK_THRESHOLD
        )
    )

    if safe:
        if flood_challenge or flood_block or brute_challenge or brute_block or graph_challenge or graph_block:
            return True, "challenge_or_rate_limit", "rule_softened"
        return False, None, None

    if flood_block or brute_block or graph_block:
        return True, "block", "rule_high_risk"

    if flood_challenge or brute_challenge or graph_challenge:
        return True, "challenge_or_rate_limit", "rule_rate_limit"

    return False, None, None


def compute_ml_action(abnormal_score: float):
    """
    ML chỉ dùng để cảnh báo/monitor.
    Không để ML tự trả 429 hoặc block vì dễ false positive khi user refresh nhiều lần.
    Rule engine mới quyết định challenge/block.
    """

    if abnormal_score >= ML_HIGH_RISK_THRESHOLD:
        return "monitor", "ml_high_risk_monitor"

    if abnormal_score >= ML_CHALLENGE_THRESHOLD:
        return "monitor", "ml_monitor"

    if abnormal_score >= ML_MONITOR_THRESHOLD:
        return "monitor", "ml_monitor"

    return "allow", "normal"


# ============================================================
# POST /predict-api-gateway
# ============================================================

@app.route("/predict-api-gateway", methods=["POST"])
def predict_api_gateway():
    if not MODEL_LOADED:
        return fallback_allow("fallback_model_not_loaded")

    data = request.get_json(force=True)

    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    action_name = str(data.get("action_name", "")).lower()

    # ========================================================
    # BUILD RAW FEATURES — phải khớp train v6
    # ========================================================
    raw_values = {
        "inter_api_access_duration(sec)": safe_float(data, "inter_api_access_duration", 0),
        "api_access_uniqueness": safe_float(data, "api_access_uniqueness", 0),
        "sequence_length(count)": safe_float(data, "sequence_length", 0),
        "vsession_duration(min)": safe_float(data, "vsession_duration", 0),
        "num_sessions": safe_float(data, "num_sessions", 1),
        "num_users": safe_float(data, "num_users", 1),
        "num_unique_apis": safe_float(data, "num_unique_apis", 0),
        "request_rate_per_min": safe_float(data, "request_rate_per_min", 0),
        "graph_num_nodes": safe_float(data, "graph_num_nodes", 0),
        "graph_num_edges": safe_float(data, "graph_num_edges", 0),
        "graph_density": safe_float(data, "graph_density", 0),
        "graph_self_loops": safe_float(data, "graph_self_loops", 0),
        "graph_avg_degree": safe_float(data, "graph_avg_degree", 0),
    }

   
    # ========================================================
    # COLD START GUARD
    # ========================================================
    seq_length = raw_values["sequence_length(count)"]
    vsession_duration = raw_values["vsession_duration(min)"]
    request_rate = raw_values["request_rate_per_min"]
    graph_edges = raw_values["graph_num_edges"]
    graph_self_loops = raw_values["graph_self_loops"]

    # Chỉ allow cold-start khi request thật sự mới.
    # Không dùng "vsession_duration < 0.1" một mình,
    # vì curl/no-cookie có thể làm session luôn mới nhưng IP sequence vẫn tăng.
    is_real_cold_start = (
        seq_length <= 2
        and request_rate <= 2
        and graph_edges <= 1
        and graph_self_loops <= 1
    )

    if is_real_cold_start:
        response = {
            "is_abnormal": False,
            "risk_score": 0,
            "attack_score": 0,
            "predicted_label": "normal",
            "rule_attack": False,
            "action": "allow",
            "decision_source": "cold_start_allow",
        }

        print(
            f"[API Gateway] 🧊 cold-start allow "
            f"seq={seq_length:.0f} rate={request_rate:.1f}/min "
            f"edges={graph_edges:.0f} loops={graph_self_loops:.0f} "
            f"vsession={vsession_duration:.3f} action={action_name}"
        )

        return jsonify(response)

    # ========================================================
    # ML PREDICT
    # ========================================================
    try:
        X = pd.DataFrame([raw_values])[feature_cols]
        probs = model.predict_proba(X)[0]

        # Binary model: [normal_prob, abnormal_prob]
        abnormal_score = float(probs[1])
        normal_score = float(probs[0])

       

        

    except Exception as e:
        return jsonify({
            "is_abnormal": False,
            "risk_score": 0,
            "attack_score": 0,
            "predicted_label": "normal",
            "rule_attack": False,
            "action": "allow",
            "decision_source": f"fallback_predict_error: {str(e)}",
        }), 200

    # ========================================================
    # RULE ACTION
    # ========================================================
    rule_attack, rule_action, rule_source = compute_rule_action(
        raw_values,
        action_name
    )

    # ========================================================
    # FINAL ACTION
    # ========================================================
    if rule_attack:
        action = rule_action
        decision_source = rule_source
    else:
        action, decision_source = compute_ml_action(abnormal_score)

    # Login/Register không hard-block kể cả logic lỗi
    if action == "block" and is_safe_action(action_name):
        action = "challenge_or_rate_limit"
        decision_source += "_softened"

    # Đồng bộ label hiển thị với policy xử lý.
    # Tránh log kiểu: Risk=0.53, Label=abnormal nhưng Action=allow, Source=normal.
    # Nếu rule bắt attack thì vẫn hiển thị abnormal dù ML score thấp.
    display_is_abnormal = abnormal_score >= ML_MONITOR_THRESHOLD or rule_attack
    display_label = "abnormal" if display_is_abnormal else "normal"

    response = {
        "is_abnormal": display_is_abnormal,
        "risk_score": round(abnormal_score, 4),
        "attack_score": round(abnormal_score, 4),
        "predicted_label": display_label,
        "rule_attack": rule_attack,
        "action": action,
        "decision_source": decision_source,
    }

    emoji = {
        "allow": "✅",
        "monitor": "👁️",
        "challenge_or_rate_limit": "⚠️",
        "block": "🚫",
    }.get(action, "❓")

    print(
        f"[API Gateway] {emoji} {display_label:<8} "
        f"normal={normal_score:.4f} abnormal={abnormal_score:.4f} "
        f"rate={raw_values['request_rate_per_min']:.1f}/min "
        f"seq={seq_length:.0f} "
        f"edges={raw_values['graph_num_edges']:.0f} "
        f"loops={raw_values['graph_self_loops']:.0f} "
        f"action={action} source={decision_source}"
    )

    return jsonify(response)


# ============================================================
# HEALTH
# ============================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok" if MODEL_LOADED else "model_not_loaded",
        "model_type": model_type,
        "features": feature_cols,
        "labels": label_names,
        "thresholds": {
            "monitor": ML_MONITOR_THRESHOLD,
            "challenge": ML_CHALLENGE_THRESHOLD,
            "high_risk": ML_HIGH_RISK_THRESHOLD,
        }
    })


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "API Gateway ML Detector v6 binary is running",
        "endpoint": "/predict-api-gateway",
        "health": "/health"
    })


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  API Gateway ML Detector v6 đang chạy tại:")
    print("  http://localhost:5001")
    print("=" * 60 + "\n")

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=False
    )