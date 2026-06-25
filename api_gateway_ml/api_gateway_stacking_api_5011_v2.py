"""
============================================================
eParty — API Gateway ML Detector 5011
New model: Stacking Ensemble

Endpoint:
  POST http://127.0.0.1:5011/predict-api-gateway

Purpose:
- Upgrade ML layer from old 5001 single selected model to new 5011 Stacking Ensemble.
- Keep output compatible with existing ASP.NET MVC C# classes.
- Expose ML-only fields for fair comparison with old model.

Important output fields:
- ml_risk_score / attack_score: pure Stacking meta-model probability (passthrough=False)
- risk_score: final production risk after combining ML score with rule risk
- base_model_scores: probability from each base estimator
- response_time_ms: inference time
============================================================
"""

import os
import time
from typing import Dict, Tuple

import joblib
import pandas as pd
from flask import Flask, jsonify, request

app = Flask(__name__)

MODEL_DIR = "models"

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

# Accept both new snake_case keys from C# and old training names with units.
INPUT_ALIASES = {
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

SAFE_ACTIONS = {"login", "register"}

# ML thresholds. Main threshold is loaded from training artifact.
ML_MONITOR_THRESHOLD = 0.55
ML_CHALLENGE_THRESHOLD = 0.80
ML_HIGH_RISK_THRESHOLD = 0.95

# Rule thresholds inherited from production 5001 style.
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

print("🚀 Đang load API Gateway Stacking model 5011...")

try:
    model = joblib.load(os.path.join(MODEL_DIR, "api_gateway_stacking_model.pkl"))
    feature_cols = joblib.load(os.path.join(MODEL_DIR, "api_gateway_features_stacking.pkl"))
    threshold = float(joblib.load(os.path.join(MODEL_DIR, "api_gateway_threshold_stacking.pkl")))
    model_type = joblib.load(os.path.join(MODEL_DIR, "api_gateway_model_type_stacking.pkl"))
    label_names = joblib.load(os.path.join(MODEL_DIR, "api_gateway_labels_stacking.pkl"))

    try:
        base_model_names = joblib.load(os.path.join(MODEL_DIR, "api_gateway_base_models_stacking.pkl"))
    except Exception:
        base_model_names = []

    MODEL_LOADED = True

    print("✅ API Gateway Stacking model loaded")
    print(f"   Model type: {model_type}")
    print(f"   Threshold : {threshold}")
    print(f"   Features  : {feature_cols}")
    print(f"   Labels    : {label_names}")
    print(f"   Base models: {base_model_names}")

except Exception as exc:
    MODEL_LOADED = False
    model = None
    feature_cols = FEATURE_COLS
    threshold = 0.5
    model_type = "stacking_ensemble_5011_not_loaded"
    label_names = ["normal", "abnormal"]
    base_model_names = []

    print(f"❌ Không load được Stacking model 5011: {exc}")
    print("   Hãy chạy train_api_gateway_stacking_5011_new.py trước!")


def safe_float(data: Dict, aliases, default=0.0) -> float:
    if isinstance(aliases, str):
        aliases = [aliases]

    for key in aliases:
        try:
            if key in data and data.get(key) is not None:
                return float(data.get(key))
        except Exception:
            continue

    return float(default)


def is_safe_action(action_name: str) -> bool:
    return str(action_name or "").lower() in SAFE_ACTIONS


def build_raw_features(data: Dict) -> Dict[str, float]:
    raw = {}

    for feature in FEATURE_COLS:
        raw[feature] = safe_float(data, INPUT_ALIASES.get(feature, feature), 0.0)

    # If request_rate_per_min is missing, compute from sequence/duration.
    if "request_rate_per_min" not in data:
        duration = raw.get("vsession_duration", 0.0)
        raw["request_rate_per_min"] = 0.0 if duration <= 0 else raw.get("sequence_length", 0.0) / duration

    return raw


def fallback_allow(reason="fallback"):
    return jsonify({
        "is_abnormal": False,
        "risk_score": 0,
        "ml_risk_score": 0,
        "attack_score": 0,
        "predicted_label": "normal",
        "rule_attack": False,
        "action": "allow",
        "decision_source": reason,
        "model": model_type,
        "threshold": threshold,
        "base_model_scores": {},
        "meta_model": "LogisticRegression_pure_stacking",
        "response_time_ms": 0,
    }), 200


def compute_rule_action(raw: Dict[str, float], action_name: str) -> Tuple[bool, str, str, float]:
    safe = is_safe_action(action_name)

    request_rate = raw["request_rate_per_min"]
    inter_duration = raw["inter_api_access_duration"]
    seq_length = raw["sequence_length"]
    graph_edges = raw["graph_num_edges"]
    graph_self_loops = raw["graph_self_loops"]

    flood_challenge = request_rate > RATE_CHALLENGE_THRESHOLD
    flood_block = request_rate > RATE_BLOCK_THRESHOLD

    brute_challenge = inter_duration < INTER_SHORT_THRESHOLD and seq_length >= 30
    brute_block = inter_duration < INTER_BLOCK_THRESHOLD and seq_length >= 100

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

    reasons = []
    if flood_challenge:
        reasons.append("rate_challenge")
    if flood_block:
        reasons.append("rate_block")
    if brute_challenge:
        reasons.append("inter_challenge")
    if brute_block:
        reasons.append("inter_block")
    if graph_challenge:
        reasons.append("graph_challenge")
    if graph_block:
        reasons.append("graph_block")

    if not reasons:
        return False, "allow", "no_rule", 0.0

    if safe:
        return True, "challenge_or_rate_limit", "rule_softened:" + ",".join(reasons), 0.85

    if flood_block or brute_block or graph_block:
        return True, "block", "rule_block:" + ",".join(reasons), 1.0

    return True, "challenge_or_rate_limit", "rule_rate_limit:" + ",".join(reasons), 0.85


def compute_ml_action(ml_score: float) -> Tuple[str, str]:
    # Production policy: ML alone monitors. Hard blocking is done by rule engine.
    # For fair model comparison, use ml_risk_score/attack_score, not final action.
    if ml_score >= ML_HIGH_RISK_THRESHOLD:
        return "monitor", "ml_high_risk_monitor"
    if ml_score >= ML_CHALLENGE_THRESHOLD:
        return "monitor", "ml_monitor"
    if ml_score >= ML_MONITOR_THRESHOLD:
        return "monitor", "ml_monitor"
    return "allow", "normal"


def is_real_cold_start(raw: Dict[str, float]) -> bool:
    return (
        raw["sequence_length"] <= 2
        and raw["request_rate_per_min"] <= 2
        and raw["graph_num_edges"] <= 1
        and raw["graph_self_loops"] <= 1
    )


def get_base_model_scores(X: pd.DataFrame) -> Dict[str, float]:
    scores = {}

    if model is None:
        return scores

    try:
        named_estimators = getattr(model, "named_estimators_", {})
        for name, estimator in named_estimators.items():
            if hasattr(estimator, "predict_proba"):
                prob = float(estimator.predict_proba(X)[0][1])
            elif hasattr(estimator, "decision_function"):
                raw_score = float(estimator.decision_function(X)[0])
                prob = 1.0 / (1.0 + pow(2.718281828, -raw_score))
            else:
                prob = float(estimator.predict(X)[0])
            scores[name] = round(prob, 4)
    except Exception:
        pass

    return scores


@app.route("/predict-api-gateway", methods=["POST"])
def predict_api_gateway():
    start_time = time.perf_counter()

    if not MODEL_LOADED:
        return fallback_allow("fallback_model_not_loaded")

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    action_name = str(data.get("action_name", "")).lower()
    raw = build_raw_features(data)

    if is_real_cold_start(raw):
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return jsonify({
            "is_abnormal": False,
            "risk_score": 0,
            "ml_risk_score": 0,
            "attack_score": 0,
            "predicted_label": "normal",
            "rule_attack": False,
            "action": "allow",
            "decision_source": "cold_start_allow",
            "model": model_type,
            "threshold": threshold,
            "base_model_scores": {},
            "meta_model": "LogisticRegression_pure_stacking",
            "response_time_ms": round(elapsed_ms, 2),
        })

    try:
        X = pd.DataFrame([raw])[feature_cols]
        probs = model.predict_proba(X)[0]
        normal_score = float(probs[0])
        ml_score = float(probs[1])
        base_scores = get_base_model_scores(X)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return jsonify({
            "is_abnormal": False,
            "risk_score": 0,
            "ml_risk_score": 0,
            "attack_score": 0,
            "predicted_label": "normal",
            "rule_attack": False,
            "action": "allow",
            "decision_source": "fallback_predict_error:" + str(exc),
            "model": model_type,
            "threshold": threshold,
            "base_model_scores": {},
            "meta_model": "LogisticRegression_pure_stacking",
            "response_time_ms": round(elapsed_ms, 2),
        }), 200

    rule_attack, rule_action, rule_source, rule_risk_score = compute_rule_action(raw, action_name)

    if rule_attack:
        action = rule_action
        decision_source = rule_source
    else:
        action, decision_source = compute_ml_action(ml_score)

    if action == "block" and is_safe_action(action_name):
        action = "challenge_or_rate_limit"
        decision_source += "_softened"

    final_risk_score = max(ml_score, rule_risk_score)
    display_is_abnormal = ml_score >= threshold or rule_attack
    predicted_label = "abnormal" if display_is_abnormal else "normal"

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    response = {
        "is_abnormal": bool(display_is_abnormal),
        "risk_score": round(final_risk_score, 4),
        "ml_risk_score": round(ml_score, 4),
        "attack_score": round(ml_score, 4),
        "normal_score": round(normal_score, 4),
        "predicted_label": predicted_label,
        "rule_attack": bool(rule_attack),
        "action": action,
        "decision_source": decision_source,
        "model": model_type,
        "threshold": threshold,
        "base_model_scores": base_scores,
        "meta_model": "LogisticRegression_pure_stacking",
        "response_time_ms": round(elapsed_ms, 2),
    }

    emoji = {
        "allow": "✅",
        "monitor": "👁️",
        "challenge_or_rate_limit": "⚠️",
        "block": "🚫",
    }.get(action, "❓")

    print(
        f"[API Gateway 5011] {emoji} {predicted_label:<8} "
        f"ml={ml_score:.4f} final={final_risk_score:.4f} "
        f"rate={raw['request_rate_per_min']:.1f}/min "
        f"seq={raw['sequence_length']:.0f} "
        f"edges={raw['graph_num_edges']:.0f} "
        f"loops={raw['graph_self_loops']:.0f} "
        f"action={action} source={decision_source} "
        f"time={elapsed_ms:.2f}ms"
    )

    return jsonify(response)


@app.route("/predict-api-gateway-ml-only", methods=["POST"])
def predict_api_gateway_ml_only():
    start_time = time.perf_counter()

    if not MODEL_LOADED:
        return fallback_allow("fallback_model_not_loaded")

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    raw = build_raw_features(data)

    try:
        X = pd.DataFrame([raw])[feature_cols]
        probs = model.predict_proba(X)[0]
        normal_score = float(probs[0])
        ml_score = float(probs[1])
        base_scores = get_base_model_scores(X)
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return jsonify({
            "error": str(exc),
            "response_time_ms": round(elapsed_ms, 2),
        }), 500

    pred = ml_score >= threshold
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return jsonify({
        "is_abnormal": bool(pred),
        "risk_score": round(ml_score, 4),
        "ml_risk_score": round(ml_score, 4),
        "attack_score": round(ml_score, 4),
        "normal_score": round(normal_score, 4),
        "predicted_label": "abnormal" if pred else "normal",
        "rule_attack": False,
        "action": "ml_only",
        "decision_source": "ml_only_stacking_5011",
        "model": model_type,
        "threshold": threshold,
        "base_model_scores": base_scores,
        "meta_model": "LogisticRegression_pure_stacking",
        "response_time_ms": round(elapsed_ms, 2),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online" if MODEL_LOADED else "model_not_loaded",
        "is_online": bool(MODEL_LOADED),
        "model_loaded": bool(MODEL_LOADED),
        "model_type": model_type,
        "port": 5011,
        "features": feature_cols,
        "labels": label_names,
        "threshold": threshold,
        "thresholds": {
            "main": threshold,
            "monitor": ML_MONITOR_THRESHOLD,
            "challenge": ML_CHALLENGE_THRESHOLD,
            "high_risk": ML_HIGH_RISK_THRESHOLD,
        },
        "base_models": base_model_names,
        "meta_model": "LogisticRegression_pure_stacking",
    })


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "API Gateway Stacking Ensemble 5011 is running",
        "endpoint": "/predict-api-gateway",
        "ml_only_endpoint": "/predict-api-gateway-ml-only",
        "health": "/health",
    })


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  API Gateway Stacking Ensemble 5011 đang chạy tại:")
    print("  http://127.0.0.1:5011")
    print("=" * 70 + "\n")

    app.run(host="0.0.0.0", port=5011, debug=False)
