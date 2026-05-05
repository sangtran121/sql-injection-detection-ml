# 🛡️ SQL Injection Detection with Machine Learning

**Hệ thống phát hiện và chặn tấn công SQL Injection bằng Machine Learning**  
Tích hợp vào dự án **Party Serv System** (ASP.NET MVC 5)

<p align="center">
  <img src="https://img.shields.io/badge/ASP.NET_MVC-5-blue?style=for-the-badge&logo=dotnet" />
  <img src="https://img.shields.io/badge/Python-Flask-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Model-XGBoost-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Accuracy-99.7%25-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/SQL_Server-red?style=for-the-badge&logo=microsoftsqlserver" />
</p>

---

## 📖 Giới thiệu

Đây là module bảo mật được phát triển cho **Party Serv System** — hệ thống quản lý tiệc cưới / sự kiện.

Thay vì chỉ dùng regex truyền thống (dễ bị bypass), hệ thống sử dụng **mô hình Machine Learning (XGBoost + TF-IDF)** để phân tích ngữ nghĩa của input, giúp phát hiện cả các tấn công obfuscated và zero-day.

**Độ chính xác mô hình**: **99.7%** trên tập test.

---

## ✨ Tính năng nổi bật

- Phát hiện thời gian thực bằng XGBoost
- Action Filter chặn request ngay trước khi vào Controller
- Logging chi tiết vào database (`SQLInjectionLogs`)
- Hỗ trợ tốt nội dung tiếng Việt (giảm false positive)
- Flask REST API độc lập, dễ scale
- Có cơ chế fallback rule-based khi API không hoạt động

---

## 🏗️ Kiến trúc hệ thống

```
Người dùng → ASP.NET MVC (SqlInjectionFilter)
                    ↓
          Gửi input đến Flask API
                    ↓
          XGBoost Model → Dự đoán
                    ↓
     Blocked (403) hoặc Allowed + Log DB
```

---

## 📁 Cấu trúc thư mục

```
sql-injection-detection-ml/
├── eParty/                             ← Dự án ASP.NET MVC chính
│   ├── Helpers/SqlInjectionFilter.cs   ← Filter bảo mật (Action Filter)
│   ├── Models/SQLInjectionLog.cs       ← Bảng log tấn công
│   └── Web.config
│
├── sql_injection_ml/                   ← Phần Machine Learning
│   ├── app.py                          ← Flask REST API
│   ├── sql_injection_detection.py      ← Script train model
│   └── models/                         ← xgboost_model.pkl + tfidf_vectorizer.pkl
│
├── ssms/                               ← Script SQL tạo bảng
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt (Dành cho người mới bắt đầu)

### Yêu cầu

- Visual Studio 2019 hoặc 2022
- .NET Framework 4.7.2+
- Python 3.8+
- SQL Server

### Bước 1: Clone repository

```bash
git clone https://github.com/sangtran121/sql-injection-detection-ml.git
cd sql-injection-detection-ml
```

### Bước 2: Chạy Flask API (Python)

Mở Terminal và chạy:

```bash
cd sql_injection_ml
pip install flask
python app.py
```

> ⚠️ **Quan trọng:** Giữ terminal này luôn mở.

### Bước 3: Chạy Web ASP.NET

1. Mở file `eParty.sln` bằng Visual Studio
2. Build Solution (`Ctrl + Shift + B`)
3. Nhấn `F5` để chạy

### Bước 4: Test hệ thống

**Test tấn công** (Nên bị chặn):

```
' OR '1'='1 --
1; DROP TABLE Events --
admin' OR 1=1 #
1 UNION/**/SELECT 1,2,3 --
pg_sleep(5)--
```

**Test bình thường** (Nên cho qua):

```
Tạo bàn in đẹp cho tiệc cưới
Menu: Gỏi cuốn - Cá kho tộ
Tiệc công ty ABC - Teambuilding 2026
```

---

## 📊 Hiệu năng Model

| Chỉ số | Kết quả |
|---|---|
| Accuracy | **99.7%** |
| Stress Test (40+ cases) | **86% – 93%** |
| Loại tấn công phát hiện tốt | Tautology, Union, Time-based, Login Bypass, Obfuscated, Schema Leak |

---

## ⚠️ Lưu ý quan trọng

- Phải chạy `app.py` trước khi chạy web ASP.NET
- Nếu Flask API không chạy, hệ thống sẽ tự động fallback về rule-based (vẫn có bảo vệ cơ bản)
- Log tấn công được lưu trong bảng `SQLInjectionLogs`

---

## 📬 Hỗ trợ

Nếu gặp lỗi:

- Kiểm tra Flask API có đang chạy trên port `5000` không
- Tạo Issue trên GitHub

---

<p align="center">
  ✅ Hoàn thành: 06/05/2026 &nbsp;|&nbsp; 👤 Người thực hiện: <strong>Sang</strong><br/>
  Made with ❤️ for Secure Party Management
</p>
