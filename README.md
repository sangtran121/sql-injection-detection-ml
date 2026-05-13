<div align="center">

# 🛡️ SQL Injection Detection — Machine Learning

**Hệ thống phát hiện và chặn tấn công SQL Injection bằng XGBoost + Rule-based Filter**  
Tích hợp vào website quản lý dịch vụ tiệc cưới **eParty** (ASP.NET MVC)

[![Python](https://img.shields.io/badge/Python-3.10%2F3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-API-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Model-FF6600?style=for-the-badge)](https://xgboost.readthedocs.io)
[![ASP.NET](https://img.shields.io/badge/ASP.NET-MVC%204.8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)

</div>

---

## 📖 Giới thiệu

Đây là phiên bản nâng cấp của dự án **Party Serv System (eParty)** — một website quản lý dịch vụ tiệc cưới được thực hiện trong môn học lập trình web tại trường đại học.

Ban đầu, dự án chỉ là một website thông thường sử dụng **C# ASP.NET MVC + Entity Framework** với các chức năng chính: đăng ký, đặt tiệc, quản lý menu, booking, thanh toán... Sau khi hoàn thành, nhóm nhận ra một lỗ hổng bảo mật rất nghiêm trọng là **SQL Injection**.

Vì vậy, nhóm quyết định **tích hợp thêm lớp bảo mật thông minh bằng Machine Learning** để hệ thống có khả năng tự động phát hiện và chặn các cuộc tấn công SQL Injection một cách chính xác.

---

## 🎯 Mục tiêu dự án

- Xây dựng website quản lý tiệc cưới hoàn chỉnh
- Tích hợp **Machine Learning (XGBoost)** để phát hiện SQL Injection
- Kết hợp **Rule-based Filter** để tăng tốc độ và độ chính xác
- Hỗ trợ tốt **tiếng Việt** — không chặn nhầm mô tả tiệc, menu, teambuilding...
- Ghi log chi tiết các cuộc tấn công vào database
- Có công cụ **test batch** để kiểm tra hiệu suất hàng loạt

---

## ✅ Kết quả đạt được

| Tiêu chí | Kết quả |
|---|---|
| Phát hiện SQL Injection | Classic, Union-based, Time-based, Error-based, Obfuscated |
| Hỗ trợ tiếng Việt | ✅ Không chặn nhầm mô tả tiệc cưới, menu, chi phí, khách mời |
| Test batch | Kiểm tra hàng trăm payload cùng lúc |
| Phạm vi bảo vệ | Form Booking, Menu, Description và toàn bộ input |
| Ghi log | ✅ Đầy đủ vào database để theo dõi |

---

## ⚙️ Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| Hệ điều hành | Windows 10 / Windows 11 |
| IDE | Visual Studio 2022 (Community Edition) |
| Framework | .NET Framework 4.8 |
| Python | **3.10 hoặc 3.11** *(không dùng 3.12)* |
| RAM | Tối thiểu 8GB *(khuyến nghị 16GB)* |
| Khác | Kết nối Internet (để cài package lần đầu) |

---

## 📂 Cấu trúc thư mục

```
sql-injection-detection-ml/
│
├── 📁 eParty/                           ← Website ASP.NET MVC chính
│   ├── Controllers/
│   ├── Helpers/
│   │   └── SqlInjectionFilter.cs        ← Logic lọc SQL Injection
│   ├── wwwroot/
│   │   └── models/                      ← Đặt 2 file .pkl vào đây ⚠️
│   └── eParty.sln
│
├── 📁 sql_injection_ml/                 ← Phần Machine Learning (Python)
│   ├── app.py                           ← Flask REST API
│   ├── sql_injection_detection.py       ← Script train model
│   └── models/                          ← Output: 2 file .pkl
│
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt từng bước

### Bước 1 — Tải source code

1. Nhấn nút **`Code`** (màu xanh) → **`Download ZIP`**
2. Giải nén ra thư mục dễ nhớ, ví dụ:
   ```
   C:\Users\TênBạn\Desktop\sql-injection-detection-ml
   ```

---

### Bước 2 — Cài đặt Python & Flask

Mở **Command Prompt** và chạy lần lượt:

```cmd
# Di chuyển vào thư mục Python
cd C:\Users\TênBạn\Desktop\sql-injection-detection-ml\sql_injection_ml

# Tạo môi trường ảo
python -m venv venv

# Kích hoạt môi trường ảo
venv\Scripts\activate

# Cài các thư viện cần thiết
pip install flask pandas scikit-learn xgboost joblib numpy
```

---

### Bước 3 — Train Model & tạo file `.pkl`

Vẫn trong thư mục `sql_injection_ml`, chạy:

```cmd
python sql_injection_detection.py
```

Chờ đến khi thấy thông báo:
```
✅ ĐÃ LƯU MODEL: sql_injection_xgboost_model.pkl
```

Lệnh trên tạo ra **2 file** trong thư mục `sql_injection_ml\models\`:
- `sql_injection_xgboost_model.pkl`
- `tfidf_vectorizer.pkl`

> **⚠️ Bước bắt buộc:** Copy cả 2 file `.pkl` vào:
> ```
> eParty\wwwroot\models\
> ```
> *(Thư mục này đã có sẵn trong project)*

---

### Bước 4 — Mở & build project Web

1. Mở **Visual Studio 2022**
2. Chọn **Open a project or solution** → mở file `eParty.sln`
3. Chờ Visual Studio load xong
4. Click chuột phải vào Solution → **Restore NuGet Packages**
5. Build: **`Ctrl + Shift + B`**

---

## ▶️ Chạy hệ thống

> **⚠️ Quan trọng:** Phải khởi động theo đúng thứ tự sau.

### 1️⃣ Khởi động Flask ML API

```cmd
cd C:\Users\TênBạn\Desktop\sql-injection-detection-ml\sql_injection_ml
venv\Scripts\activate
python app.py
```

> Giữ cửa sổ này **luôn mở** trong suốt quá trình sử dụng.

### 2️⃣ Khởi động Website ASP.NET

Trong Visual Studio:
- Click chuột phải project `eParty` → **Set as Startup Project**
- Nhấn **`F5`** để chạy

Website sẽ mở tại: **`https://localhost:44350`**

---

## 🧪 Cách test hệ thống

1. Truy cập: `https://localhost:44350/SqlInjectionTest/Index`
2. Dán payload vào ô textarea
3. Chọn chế độ kiểm tra:

| Chế độ | Mô tả |
|---|---|
| **Only ML** | Kiểm tra thuần bằng Machine Learning |
| **Full Filter** | Giả lập filter thực tế trên website (ML + Rule-based) |

4. Nhấn **"CHẠY TEST HÀNG LOẠT"**

---

## 🛠️ Khắc phục lỗi thường gặp

<details>
<summary><b>❌ Lỗi: <code>No module named flask</code></b></summary>

Chạy lại lệnh cài thư viện:
```cmd
pip install flask
```
</details>

<details>
<summary><b>❌ Lỗi: Website load mãi không ra</b></summary>

Đảm bảo `app.py` (Flask) đang chạy **trước khi** mở website. Kiểm tra cửa sổ CMD xem Flask đã khởi động chưa.
</details>

<details>
<summary><b>❌ Lỗi: Không tìm thấy file <code>.pkl</code></b></summary>

Kiểm tra lại xem đã copy đúng 2 file `.pkl` vào thư mục `eParty\wwwroot\models\` chưa.
</details>

---

## 🔍 Hệ thống hoạt động như thế nào?

```
Request từ người dùng
        │
        ▼
┌────────────────────┐
│  Rule-based Filter │  ← Chặn ngay các pattern rõ ràng (nhanh)
└─────────┬──────────┘
          │ Không chắc chắn
          ▼
┌────────────────────┐
│   Flask ML API     │  ← Gửi payload đến XGBoost model
└─────────┬──────────┘
          │
     ┌────┴────┐
     ▼         ▼
  CHẶN ⛔   CHO QUA ✅
     │
     ▼
Ghi log vào Database
```

---

<div align="center">

Nếu gặp lỗi ở bước nào, hãy mở một **[Issue](https://github.com/sangtran121/sql-injection-detection-ml/issues)** kèm ảnh chụp màn hình — mình sẽ hỗ trợ ngay!

**Chúc bạn thành công! 🎉**

</div>
