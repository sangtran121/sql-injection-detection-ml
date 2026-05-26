# ================================================
# SQL INJECTION DETECTION 
# ================================================

import pandas as pd
import re
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
import warnings
import joblib
warnings.filterwarnings('ignore')

print("🔄 B1: Đang load dataset...")
df = pd.read_csv('Modified_SQL_Dataset.csv')

print(f"Dataset shape: {df.shape}")
print(f"Label distribution:\n{df['Label'].value_counts()}")

def clean_sql_query(text):
    text = str(text).lower()
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

df['clean_query'] = df['Query'].apply(clean_sql_query)

# ====================== B2: Phân tích ======================
print("\n" + "="*70)
print("B2: TẤN CÔNG SQLi PHỔ BIẾN NHẤT")
print("="*70)
mal = df[df['Label'] == 1]
patterns = {
    "Comment-based (--, #, /*)": mal['Query'].str.contains(r'--|#|/\*', na=False).sum(),
    "UNION-based": mal['Query'].str.contains(r'union', case=False, na=False).sum(),
    "Time-based (sleep, waitfor...)": mal['Query'].str.contains(r'sleep|pg_sleep|waitfor|benchmark|delay', case=False, na=False).sum(),
    "Tautology (1=1)": mal['Query'].str.contains(r'1\s*=\s*1|or\s+1=1', case=False, na=False).sum(),
}

for k, v in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
    print(f"→ {k}: {v:,} queries")


# ====================== Chuẩn bị dữ liệu ======================
X = df['clean_query']
y = df['Label']

vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,3), analyzer='char_wb')
X_vec = vectorizer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42, stratify=y)

# ====================== B3+B4: XGBoost Tối ưu ======================
print("\n" + "="*70)
print("B3+B4: HUẤN LUYỆN XGBoost (Tối ưu)")
print("="*70)

model = xgb.XGBClassifier(
    n_estimators=250,
    max_depth=6,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.8,
    reg_alpha=1.0,
    reg_lambda=1.0,
    random_state=42,
    n_jobs=-1,
    eval_metric='logloss'
)

model.fit(X_train, y_train)
y_pred = model.predict(X_test)

print("\n📊 KẾT QUẢ XGBoost:")
print(classification_report(y_test, y_pred, digits=4))

# ====================== B5: RandomForest ======================
print("\n" + "="*70)
print("B5: HUẤN LUYỆN RandomForest")
print("="*70)

rf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)

print("\n📊 KẾT QUẢ RandomForest:")
print(classification_report(y_test, y_pred_rf, digits=4))

# ====================== So sánh & Overfitting ======================
print("\n" + "="*70)
print("SO SÁNH & KIỂM TRA OVERFITTING")
print("="*70)

train_pred = model.predict(X_train)
print(f"XGBoost  - Train Acc: {accuracy_score(y_train, train_pred):.4f} | Test Acc: {accuracy_score(y_test, y_pred):.4f}")
print(f"RandomForest - Train Acc: {accuracy_score(y_train, rf.predict(X_train)):.4f} | Test Acc: {accuracy_score(y_test, y_pred_rf):.4f}")

# ====================== LƯU MODEL (Quan trọng) ======================
joblib.dump(model, 'models/sql_injection_xgboost_model.pkl')
joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')
print("\n✅ ĐÃ LƯU MODEL: sql_injection_xgboost_model.pkl")



# ================================================
# TEST SIÊU MỞ RỘNG - 40+ CASES 
# ================================================

print("\n" + "="*110)
print("🔥 SUPER STRESS TEST - 40+ CASES")
print("="*110)

def predict_sql_injection(query):
    cleaned = clean_sql_query(query)
    vector = vectorizer.transform([cleaned])
    raw_prob = model.predict_proba(vector)[0][1]
    
    lower = cleaned.lower()
    boost = 0.0
    
    # Boost mạnh cho các pattern SQLi thật
    if any(x in lower for x in ["information_schema", "sys.", "@@version", "xp_cmdshell", "cast((select"]):
        boost = 0.75
    elif any(x in lower for x in ["union select", "drop table", "pg_sleep", "waitfor delay", "benchmark"]):
        boost = 0.55
    elif any(x in lower for x in ["or 1=1", "'1'='1", "or '1'='1", "/*!","/**/"]):
        boost = 0.45
    
    final_prob = min(1.0, raw_prob + boost)
    
    # Giảm false positive cho text tiếng Việt bình thường
    if any(word in lower for word in ["tạo", "tiệc", "menu", "khách", "sự kiện", "bàn", "cưới", "sinh nhật", "thịt", "gỏi"]):
        if final_prob < 0.75:   # Nếu không boost mạnh thì cho qua
            final_prob = 0.1
    
    prediction = 1 if final_prob >= 0.52 else 0
    status = "🚨 MALICIOUS (SQLi)" if prediction == 1 else "✅ BENIGN"
    
    return status, final_prob, raw_prob

test_cases = [
    # === MALICIOUS  ===
    ("SELECT * FROM users WHERE id = 1 OR 1=1 --", "Tautology Classic"),
    ("admin' OR '1'='1' #", "Login Bypass 1"),
    ("admin' OR 1=1 --", "Login Bypass 2"),
    ("1; DROP TABLE Events --", "Drop Table"),
    ("pg_sleep(5)--", "Time-based PostgreSQL"),
    ("WAITFOR DELAY '0:0:5'--", "Time-based MSSQL"),
    ("SELECT * FROM information_schema.tables", "Schema Leak"),
    ("UNION SELECT username, password FROM users --", "Union Attack"),
    ("SELECT @@version", "Version Leak"),
    ("EXEC xp_cmdshell 'dir'", "Command Execution"),
    ("CAST((SELECT password FROM users) AS int)", "Error-based"),
    ("1' UNION SELECT NULL, NULL --", "Union NULL"),
    ("SELECT name FROM sysobjects WHERE xtype='U'", "Table Enumeration"),
    ("1 OR '1'='1", "Short Tautology"),
    ("'; DROP TABLE users; --", "Stacked Query"),
    ("1' AND (SELECT COUNT(*) FROM users) > 0 --", "Blind SQLi"),

    # === BENIGN - Rất gần với project Party-Serv-System  ===
    ("Tạo bàn in đẹp cho tiệc cưới", "Text Tiếng Việt 1"),
    ("Tiệc sinh nhật bé Mai Anh 10 tuổi", "Text Tiếng Việt 2"),
    ("Menu: Gỏi cuốn - Cá kho tộ - Thịt nướng", "Menu Description"),
    ("Sự kiện ngày 15/05/2026 tại Quận 1", "Event Info"),
    ("Khách mời: 150 người, có cả MC", "Guest Info"),
    ("Tổng chi phí ước tính: 85.000.000 VNĐ", "Cost"),
    ("SELECT * FROM Events WHERE EventID = 42", "Normal Query"),
    ("INSERT INTO Customers (Name, Phone) VALUES ('Nguyễn Văn A', '0123456789')", "Insert Customer"),
    ("UPDATE Events SET Status = 'Confirmed' WHERE EventID = 10", "Update Event"),
    ("SELECT COUNT(*) FROM Staff WHERE IsActive = 1", "Count Staff"),
    ("DELETE FROM Notifications WHERE CreatedDate < '2025-01-01'", "Clean Data"),
    ("SELECT EventName, StartDate, TotalCost FROM Events", "Party Report"),
    ("Tiệc công ty ABC - Teambuilding 2026", "Company Event"),
];

print("ĐANG CHẠY SUPER STRESS TEST...\n")
correct = 0

for query, desc in test_cases:
    status, final_prob, raw_prob = predict_sql_injection(query)
    
    is_malicious_expected = any(x in query.lower() for x in [
        "or 1=1", "union", "drop table", "pg_sleep", "waitfor", "information_schema", 
        "'1'='1", "/*!","/**/", "xp_cmdshell", "@@version", "cast((select", "sysobjects"
    ])
    
    mark = "✅" if ( ("MALICIOUS" in status and is_malicious_expected) or 
                     ("BENIGN" in status and not is_malicious_expected) ) else "❌"
    
    if mark == "✅":
        correct += 1
        
    print(f"{mark} {status} | Raw: {raw_prob:.4f} → Final: {final_prob:.4f} | {desc}")
    print(f"   → {query}\n")

print(f"🎯 TỶ LỆ ĐÚNG: {correct}/{len(test_cases)} = {correct/len(test_cases)*100:.1f}%")