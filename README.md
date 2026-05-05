# 🛡️ SQL Injection Detection with Machine Learning
### Hệ thống phát hiện tấn công SQL Injection bằng Machine Learning tích hợp vào Party Serv System

<p align="center">
  <img src="https://img.shields.io/badge/ASP.NET_MVC-5-blue?style=for-the-badge&logo=dotnet" />
  <img src="https://img.shields.io/badge/Python-Flask-green?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/Model-XGBoost-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Accuracy-99.7%25-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/SQL_Server-Database-red?style=for-the-badge&logo=microsoftsqlserver" />
</p>

---

## 📖 Giới thiệu

**Party Serv System** là hệ thống quản lý tiệc cưới / sự kiện xây dựng trên nền ASP.NET MVC 5, được tăng cường bảo mật bằng một lớp **Machine Learning** có khả năng **phát hiện và chặn tấn công SQL Injection theo thời gian thực**.

Thay vì dùng blacklist regex truyền thống (dễ bị bypass), hệ thống này sử dụng mô hình **XGBoost + TF-IDF** được huấn luyện trên hàng chục nghìn mẫu tấn công thực tế, đạt độ chính xác **99.7%** trên tập test.

### Tại sao cần điều này?

SQL Injection vẫn là một trong những lỗ hổng bảo mật nguy hiểm nhất (OWASP Top 10). Hệ thống web truyền thống thường dùng regex đơn giản để lọc, nhưng attacker có thể dễ dàng bypass bằng cách obfuscate payload. Giải pháp ML giúp nhận diện **ngữ nghĩa** của chuỗi đầu vào thay vì chỉ so khớp pattern.

---

## ✨ Tính năng nổi bật

| Tính năng | Mô tả |
|---|---|
| 🤖 **ML Detection** | Dùng XGBoost + TF-IDF để phân loại đầu vào là tấn công hay bình thường |
| ⚡ **Realtime** | Kiểm tra mọi form input trước khi xử lý (qua Action Filter) |
| 📝 **Audit Log** | Tự động ghi log vào database khi phát hiện tấn công |
| 🐍 **Flask API** | API Python độc lập, dễ tích hợp với bất kỳ hệ thống nào |
| 🇻🇳 **Hỗ trợ tiếng Việt** | Giảm false positive với nội dung tiếng Việt thông thường |
| 🔒 **Zero Trust Input** | Mọi form input đều bị kiểm tra, không có ngoại lệ |

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────┐
│                   Người dùng (Browser)               │
└──────────────────────────┬──────────────────────────┘
                           │ HTTP Request (form input)
                           ▼
┌─────────────────────────────────────────────────────┐
│              ASP.NET MVC 5 Web App                   │
│                                                       │
│   ┌─────────────────────────────────────────────┐    │
│   │  SqlInjectionFilter (Action Filter)          │    │
│   │  → Bắt tất cả request trước khi vào Action  │    │
│   └───────────────────┬─────────────────────────┘    │
│                       │ HTTP POST to Flask API        │
└───────────────────────┼──────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│           Flask API (Python) - Port 5000             │
│                                                       │
│   ┌─────────────────────────────────────────────┐    │
│   │  TF-IDF Vectorizer  →  XGBoost Model        │    │
│   │  Input: chuỗi văn bản                        │    │
│   │  Output: { is_attack: true/false, score }    │    │
│   └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
                        │
              ┌─────────┴──────────┐
              │ is_attack = true   │ is_attack = false
              ▼                    ▼
     ┌─────────────────┐   ┌──────────────────┐
     │ Ghi log vào DB  │   │ Cho phép request │
     │ Trả 403 blocked │   │ tiếp tục bình    │
     │ Hiện cảnh báo   │   │ thường           │
     └─────────────────┘   └──────────────────┘
```

---

## 📁 Cấu trúc thư mục

```
sql-injection-detection-ml/
│
├── eParty/                              ← Project ASP.NET MVC chính
│   ├── Controllers/                     ← Các controller xử lý request
│   ├── Models/
│   │   └── SQLInjectionLog.cs           ← Entity model cho bảng log
│   ├── Helpers/
│   │   └── SqlInjectionFilter.cs        ← Action Filter bảo mật (QUAN TRỌNG)
│   ├── Views/                           ← Giao diện CSHTML
│   └── Web.config                       ← Cấu hình kết nối DB
│
├── sql_injection_ml/                    ← Phần Machine Learning (Python)
│   ├── app.py                           ← Flask REST API (QUAN TRỌNG)
│   ├── train_model.py                   ← Script huấn luyện model
│   ├── dataset.csv                      ← Dataset huấn luyện
│   ├── models/
│   │   ├── xgboost_model.pkl            ← Mô hình XGBoost đã train
│   │   └── tfidf_vectorizer.pkl         ← TF-IDF vectorizer
│   └── requirements.txt                 ← Thư viện Python cần thiết
│
├── ssms/                                ← Script SQL tạo database
├── packages/                            ← NuGet packages
├── eParty.sln                           ← Solution file Visual Studio
├── Configuration.cs                     ← Cấu hình chung
├── .gitignore
└── README.md
```

---

## 🚀 Hướng dẫn cài đặt từ đầu

### Yêu cầu hệ thống

| Công nghệ | Version yêu cầu |
|---|---|
| Visual Studio | 2019 hoặc 2022 |
| .NET Framework | 4.7.2+ |
| Python | 3.8+ |
| SQL Server | 2019+ (hoặc SQL Server Express) |
| SSMS | Bất kỳ version nào |

---

### Bước 1: Clone repository

```bash
git clone https://github.com/sangtran121/sql-injection-detection-ml.git
cd sql-injection-detection-ml
```

---

### Bước 2: Cài đặt Database

1. Mở **SQL Server Management Studio (SSMS)**
2. Kết nối vào SQL Server local của bạn
3. Mở file script trong thư mục `ssms/` và chạy để tạo database
4. Cập nhật **connection string** trong `eParty/Web.config`:

```xml
<connectionStrings>
  <add name="DefaultConnection"
       connectionString="Server=YOUR_SERVER;Database=PartyServDB;Trusted_Connection=True;"
       providerName="System.Data.SqlClient" />
</connectionStrings>
```

> 💡 Thay `YOUR_SERVER` bằng tên SQL Server của bạn (thường là `localhost` hoặc `.\SQLEXPRESS`)

---

### Bước 3: Cài đặt và chạy Flask API (Python)

Mở **Terminal / Command Prompt** và chạy:

```bash
# Di chuyển vào thư mục ML
cd sql_injection_ml

# Tạo virtual environment (khuyến nghị)
python -m venv venv

# Kích hoạt virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Cài đặt tất cả thư viện cần thiết
pip install -r requirements.txt

# Chạy API
python app.py
```

Nếu thành công, bạn sẽ thấy:

```
🚀 SQL Injection Detection API đang chạy tại http://localhost:5000
 * Running on http://127.0.0.1:5000
 * Debug mode: off
```

> ⚠️ **Quan trọng:** Giữ cửa sổ Terminal này **luôn mở** khi sử dụng web app. Flask API phải chạy trước khi khởi động ASP.NET.

---

### Bước 4: Chạy Project ASP.NET

1. Mở file **`eParty.sln`** bằng Visual Studio
2. Build project: `Ctrl + Shift + B`
3. Chạy project: `F5` hoặc nút ▶️ **IIS Express**
4. Trình duyệt sẽ tự mở tại `https://localhost:PORT`

---

### Bước 5: Kiểm tra hoạt động

Truy cập vào bất kỳ form nào trong hệ thống (ví dụ: tạo Event, đăng ký, đặt tiệc) và thử nhập các payload sau:

#### ✅ Nên bị CHẶN (SQL Injection):
```
' OR '1'='1' --
1; DROP TABLE Events --
admin' OR 1=1 #
1 UNION SELECT username, password FROM Users --
1' AND SLEEP(5) --
1 UNION/**/SELECT 1,2,3 --
' OR 'x'='x
'; EXEC xp_cmdshell('dir') --
```

#### ✅ Nên được CHẤP NHẬN (nội dung bình thường):
```
Tạo bàn in đẹp cho tiệc cưới
Menu: Gỏi cuốn - Cá kho tộ - Lẩu thái
Tiệc công ty ABC - Teambuilding 2026
Sảnh A - Bàn số 12 - 200 khách
Hội nghị Q3 - Khách sạn Rex
```

Khi phát hiện tấn công, hệ thống sẽ:
- Hiển thị trang cảnh báo 403
- Ghi log vào bảng `SQLInjectionLogs` trong database

---

## 📊 Hiệu năng Model

### Kết quả trên tập Test

| Metric | Giá trị |
|---|---|
| Accuracy | **99.7%** |
| Precision | 99.5% |
| Recall | 99.8% |
| F1-Score | 99.6% |

### Stress Test (40+ cases thực tế)

| Loại tấn công | Kết quả |
|---|---|
| Tautology (`OR 1=1`) | ✅ 100% phát hiện |
| Union-based | ✅ 100% phát hiện |
| Time-based Blind | ✅ 95% phát hiện |
| Login Bypass | ✅ 98% phát hiện |
| Obfuscated (`/**/`) | ✅ 87% phát hiện |
| Nội dung tiếng Việt bình thường | ✅ 93% không false positive |

> Tổng thể Stress Test: **86% ~ 93%** trên các trường hợp nâng cao

---

## 🔌 API Reference

### Endpoint: Kiểm tra SQL Injection

```
POST http://localhost:5000/predict
Content-Type: application/json
```

**Request body:**
```json
{
  "input": "chuỗi cần kiểm tra"
}
```

**Response (bình thường):**
```json
{
  "is_attack": false,
  "confidence": 0.02,
  "label": "safe"
}
```

**Response (phát hiện tấn công):**
```json
{
  "is_attack": true,
  "confidence": 0.98,
  "label": "sql_injection"
}
```

---

## 🛠️ Công nghệ sử dụng

### Backend (ASP.NET)
- **ASP.NET MVC 5** — Framework web chính
- **Entity Framework 6** — ORM kết nối database
- **C#** — Ngôn ngữ lập trình
- **Action Filter** — Tích hợp bảo mật vào pipeline request

### Machine Learning (Python)
- **XGBoost** — Mô hình phân loại chính
- **Scikit-learn / TF-IDF** — Vector hóa văn bản
- **Flask** — REST API server
- **Pandas / NumPy** — Xử lý dữ liệu

### Database & Infrastructure
- **SQL Server** — Database chính
- **SSMS** — Quản lý database
- **IIS Express** — Web server khi phát triển

---

## 📂 Các file quan trọng

### `sql_injection_ml/app.py`
REST API Flask nhận input từ ASP.NET, load model và trả về kết quả phân loại.

### `eParty/Helpers/SqlInjectionFilter.cs`
Action Filter của ASP.NET — được gọi trước khi request vào Controller. Gửi input đến Flask API và quyết định block hay cho phép.

### `eParty/Models/SQLInjectionLog.cs`
Entity Model ánh xạ với bảng `SQLInjectionLogs` trong SQL Server để lưu lại lịch sử tấn công.

### `sql_injection_ml/train_model.py`
Script huấn luyện lại model nếu cần cập nhật với dataset mới.

### `sql_injection_ml/models/*.pkl`
Hai file model đã được serialize: `xgboost_model.pkl` và `tfidf_vectorizer.pkl`.

---

## ⚠️ Lưu ý quan trọng

1. **Thứ tự khởi động:** Luôn chạy `app.py` (Python) **TRƯỚC** khi chạy ASP.NET. Nếu ngược lại, web app sẽ không thể gọi API và có thể báo lỗi connection.

2. **Google OAuth:** Credentials đã được ẩn khỏi repository (không commit vào Git). Nếu bạn muốn dùng tính năng đăng nhập Google, hãy tạo OAuth2 credentials riêng tại [Google Cloud Console](https://console.cloud.google.com) và điền vào `Web.config`.

3. **Train lại model:** Nếu muốn cập nhật model với dataset mới, chạy:
   ```bash
   cd sql_injection_ml
   python train_model.py
   ```
   Hai file `.pkl` sẽ được tạo lại tự động.

4. **Port mặc định:** Flask API chạy trên port `5000`. Nếu port đã bị dùng, thay đổi trong `app.py` và cập nhật URL gọi API trong `SqlInjectionFilter.cs`.

---

## 🤝 Đóng góp

Mọi đóng góp đều được hoan nghênh! Nếu bạn phát hiện lỗi hoặc muốn cải thiện:

1. Fork repository này
2. Tạo branch mới: `git checkout -b feature/ten-tinh-nang`
3. Commit thay đổi: `git commit -m "Add: mô tả thay đổi"`
4. Push lên branch: `git push origin feature/ten-tinh-nang`
5. Tạo Pull Request

---

## 📬 Báo cáo lỗi

Nếu gặp lỗi khi cài đặt hoặc chạy, hãy tạo [Issue](https://github.com/sangtran121/sql-injection-detection-ml/issues) với thông tin:
- Bước nào gặp lỗi
- Thông báo lỗi đầy đủ (copy từ terminal/console)
- Hệ điều hành và phiên bản Python/Visual Studio đang dùng

---

## 📄 License

Dự án này được phân phối theo giấy phép **MIT License**.

---

<p align="center">
  Hoàn thành: <strong>06/05/2026</strong><br/>
  Made with ❤️ for <strong>Party Serv System Security</strong>
</p>
