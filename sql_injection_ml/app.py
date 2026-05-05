from flask import Flask, request, jsonify
import joblib
import re
import os

app = Flask(__name__)

# Load model
model_path = os.path.join('models', 'sql_injection_xgboost_model.pkl')
vectorizer_path = os.path.join('models', 'tfidf_vectorizer.pkl')

model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

def clean_sql_query(text):
    text = str(text).lower()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({"error": "Missing 'query' field"}), 400

        query = data['query']
        cleaned = clean_sql_query(query)
        
        vector = vectorizer.transform([cleaned])
        prob = float(model.predict_proba(vector)[0][1])
        
        # Threshold + Boosting
        is_sqli = prob > 0.52
        
        return jsonify({
            "is_sql_injection": is_sqli,
            "probability": round(prob, 4),
            "status": "blocked" if is_sqli else "allowed"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("🚀 SQL Injection Detection API đang chạy tại http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)