# 🛡️ eParty — SQL Injection Detection với Machine Learning

Hệ thống phát hiện và ngăn chặn tấn công SQL Injection theo thời gian thực, tích hợp vào website quản lý dịch vụ tiệc cưới **eParty** (ASP.NET MVC).

[![Python](https://img.shields.io/badge/Python-3.10%2F3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-API-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![XGBoost](https://img.shields.io/badge/XGBoost-ML%20Model-FF6600?style=for-the-badge)](https://xgboost.readthedocs.io)
[![ASP.NET](https://img.shields.io/badge/ASP.NET-MVC%204.8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)](https://dotnet.microsoft.com)
[![Telegram](https://img.shields.io/badge/Telegram-Bot%20Alert-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://core.telegram.org/bots)

---

## 📖 Giới thiệu

**eParty** là website quản lý dịch vụ tiệc cưới được xây dựng bằng **C# ASP.NET MVC + Entity Framework**, với các chức năng: đăng ký tài khoản, đặt tiệc, quản lý menu, booking, thanh toán...

Sau khi hoàn thiện website, nhóm phát hiện lỗ hổng **SQL Injection** nghiêm trọng và quyết định nâng cấp hệ thống bảo mật với 3 lớp phòng thủ:

- **Lớp 1 — Rule-based Filter:** Chặn ngay các pattern SQLi rõ ràng (nhanh, không cần gọi API)
- **Lớp 2 — ML Model (XGBoost):** Phát hiện các biến thể tinh vi, obfuscated payloads
- **Lớp 3 — Admin Review (Telegram):** Cho phép Admin xem xét và whitelist các false positive theo thời gian thực

---

## 🎯 Tính năng nổi bật

| Tính năng | Mô tả |
|-----------|-------|
| **3 lớp bảo vệ** | Rule-based → ML Model → Admin Review |
| **Phát hiện đa dạng** | Classic, Union-based, Time-based, Error-based, Obfuscated SQLi |
| **Hỗ trợ tiếng Việt** | Không chặn nhầm mô tả tiệc cưới, menu, chi phí, teambuilding |
| **Telegram Bot** | Alert real-time với nút ✅ Whitelist / ❌ Bỏ qua cho Admin |
| **Auto-retry** | Sau khi Admin whitelist, trang tự động retry request gốc |
| **Polling** | Trang 403 tự polling 3 giây, phát hiện approval → redirect |
| **Dashboard log** | Ghi đầy đủ IP, URL, payload, loại tấn công vào database |
| **Webhook callback** | Admin bấm nút Telegram → whitelist ngay không cần đăng nhập web |

---

## ⚙️ Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|-----------|---------|
| Hệ điều hành | Windows 10 / Windows 11 |
| IDE | Visual Studio 2022 (Community Edition) |
| Framework | .NET Framework 4.8 |
| Python | **3.10 hoặc 3.11** *(không dùng 3.12+)* |
| RAM | Tối thiểu 8GB *(khuyến nghị 16GB)* |
| Telegram | Bot token + Chat ID (xem hướng dẫn bên dưới) |
| ngrok | Tùy chọn — chỉ cần nếu muốn Admin bấm nút Telegram từ điện thoại |

---

## 📂 Cấu trúc thư mục

```
eParty/
│
├── 📁 Controllers/
│   ├── SQLInjectionLogController.cs     ← Dashboard log + ReportFalsePositive
│   ├── TelegramWebhookController.cs     ← Nhận callback khi Admin bấm nút Telegram
│   └── ... (các controller khác)
│
├── 📁 Helpers/
│   ├── SqlInjectionFilter.cs            ← Core: Rule-based + ML + Whitelist
│   └── TelegramHelper.cs               ← Gửi alert + inline keyboard lên Telegram
│
├── 📁 Models/
│   ├── SQLInjectionLog.cs              ← Model ghi log tấn công
│   ├── PendingWhitelist.cs             ← Model lưu token whitelist pending
│   └── AppDbContext.cs                 ← DbContext (có 2 bảng trên)
│
├── 📁 Views/Shared/
│   └── SQLInjectionBlocked.cshtml      ← Trang 403 (có nút Báo cáo + auto-retry)
│
├── 📁 sql_injection_ml/                ← Phần Machine Learning (Python)
│   ├── app.py                          ← Flask REST API (port 5000)
│   ├── sql_injection_detection.py      ← Script train XGBoost model
│   ├── Modified_SQL_Dataset.csv        ← Dataset huấn luyện
│   └── models/
│       ├── sql_injection_xgboost_model.pkl
│       └── tfidf_vectorizer.pkl
│
└── README.md
```

---

## 🏗️ Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────────────┐
│                    Request từ người dùng                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              SqlInjectionFilter (ActionFilter)               │
│                                                             │
│  Bước 0: Bypass whitelist (SQLInjectionLog, TestPage)        │
│                    │                                        │
│                    ▼                                        │
│  Bước 1: Dynamic Whitelist — payload đã được Admin duyệt?   │
│                    │ Không                                  │
│                    ▼                                        │
│  Bước 2: Rule-based (raw input) — pattern rõ ràng?          │
│                    │ Không                                  │
│                    ▼                                        │
│  Bước 3: Normalize (decode URL, strip /**/ comments)         │
│                    │                                        │
│                    ▼                                        │
│  Bước 4: Rule-based (normalized) — sau khi unescape?        │
│                    │ Không                                  │
│                    ▼                                        │
│  Bước 5: Vietnamese Whitelist — text tiếng Việt thuần túy?  │
│                    │ Không                                  │
│                    ▼                                        │
│  Bước 6: Flask ML API (XGBoost) — prob > 0.55?              │
└──────────────────────────────────────────────────────────────┘
          │ Bị chặn                        │ An toàn
          ▼                                ▼
┌──────────────────────┐         ┌──────────────────────┐
│  Ghi log vào DB      │         │  Request được xử lý  │
│  Hiện trang 403      │         │  bình thường ✅       │
│  Lưu PendingWhitelist│         └──────────────────────┘
└──────────┬───────────┘
           │ User bấm "Báo cáo Sai"
           ▼
┌──────────────────────┐
│  Telegram Bot Alert  │
│  + 2 nút inline:     │
│  ✅ Whitelist         │
│  ❌ Bỏ qua            │
└──────────┬───────────┘
           │ Admin bấm ✅
           ▼
┌──────────────────────┐
│  Webhook callback    │
│  → Whitelist token   │
│  → Polling phát hiện │
│  → Auto-retry request│
└──────────────────────┘
```

---

## 🚀 Hướng dẫn cài đặt

### Bước 1 — Tải source code

```bash
git clone https://github.com/sangtran121/sql-injection-detection-ml.git
cd sql-injection-detection-ml
```

Hoặc nhấn **Code → Download ZIP**, giải nén ra thư mục dễ nhớ.

---

### Bước 2 — Cài đặt Python & Flask

Mở **Command Prompt**, chạy lần lượt:

```cmd
cd sql_injection_ml

python -m venv venv
venv\Scripts\activate

pip install flask pandas scikit-learn xgboost joblib numpy
```

---

### Bước 3 — Train model & tạo file `.pkl`

```cmd
python sql_injection_detection.py
```

Chờ đến khi thấy:

```
✅ ĐÃ LƯU MODEL: sql_injection_xgboost_model.pkl
```

Hai file được tạo trong `sql_injection_ml\models\`:
- `sql_injection_xgboost_model.pkl`
- `tfidf_vectorizer.pkl`

> ⚠️ **Bắt buộc:** Copy cả 2 file `.pkl` vào thư mục `eParty\wwwroot\models\`

---

### Bước 4 — Cấu hình database

Mở **Package Manager Console** trong Visual Studio:

```powershell
Add-Migration InitialCreate
Add-Migration AddPendingWhitelist
Update-Database
```

Kiểm tra trong SQL Server Management Studio — phải có 2 bảng mới:
- `SQLInjectionLogs`
- `PendingWhitelists`

---

### Bước 5 — Cấu hình Telegram Bot

**5.1 Tạo bot:**
1. Nhắn tin `/newbot` cho [@BotFather](https://t.me/BotFather) trên Telegram
2. Đặt tên bot, nhận **Bot Token**

**5.2 Lấy Chat ID:**
- Nhắn bất kỳ tin nhắn cho bot, rồi truy cập:
  ```
  https://api.telegram.org/bot<TOKEN>/getUpdates
  ```
- Tìm giá trị `"id"` trong `"chat"` — đó là Chat ID của bạn

**5.3 Điền vào `TelegramHelper.cs`:**

```csharp
private static readonly string BotToken = "YOUR_BOT_TOKEN_HERE";
private static readonly string ChatId   = "YOUR_CHAT_ID_HERE";
```

---

### Bước 6 — Mở & build project Web

1. Mở **Visual Studio 2022**
2. Chọn **Open a project or solution** → mở file `eParty.sln`
3. Click chuột phải vào Solution → **Restore NuGet Packages**
4. Build: `Ctrl + Shift + B`

---

## ▶️ Chạy hệ thống

> ⚠️ **Phải khởi động đúng thứ tự:**

### 1️⃣ Khởi động Flask ML API

```cmd
cd sql_injection_ml
venv\Scripts\activate
python app.py
```

Giữ cửa sổ này **luôn mở**. Flask chạy tại `http://localhost:5000`.

### 2️⃣ Khởi động Website ASP.NET

Trong Visual Studio:
- Click chuột phải project `eParty` → **Set as Startup Project**
- Nhấn `F5`

Website mở tại: `https://localhost:44350`

### 3️⃣ (Tùy chọn) Bật ngrok để Admin bấm nút Telegram từ điện thoại

```cmd
ngrok http --host-header=rewrite https://localhost:44350
```

Sau đó đăng ký webhook (thay URL ngrok của bạn):

```
https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://YOUR_NGROK_URL/TelegramWebhook
```

> 💡 **Lưu ý:** ngrok free tier đổi URL mỗi lần restart. Phải đăng ký lại webhook sau mỗi lần bật ngrok.

---

## 🔄 Luồng hoạt động đầy đủ

```
1. Người dùng submit form có chứa nội dung đáng ngờ
         │
         ▼
2. SqlInjectionFilter chặn → hiển thị trang 403
   (Lưu token + returnUrl + formData vào PendingWhitelists)
         │
         ▼
3. Người dùng bấm "Báo cáo Sai cho Admin"
         │
         ▼
4. Telegram nhận alert với payload đầy đủ + 2 nút bấm
   ✅ Whitelist payload này    ❌ Bỏ qua
         │
         │ Admin bấm ✅
         ▼
5. Webhook /TelegramWebhook nhận callback
   → AddToWhitelist(payload)
   → Đánh dấu token IsUsed = true
         │
         ▼
6. Trang 403 đang polling mỗi 3 giây phát hiện IsUsed = true
   → Tự động replay request gốc (GET redirect / POST form submit)
         │
         ▼
7. Request thực hiện thành công ✅ — người dùng không cần nhập lại gì
```

---

## 🧪 Cách test hệ thống

### Test trang SQLInjectionTest

Truy cập: `https://localhost:44350/SqlInjectionTest/Index`

Dán payload vào textarea và chọn chế độ:

| Chế độ | Mô tả |
|--------|-------|
| **Only ML** | Kiểm tra thuần bằng XGBoost Model |
| **Full Filter** | Giả lập filter thực tế (Rule-based + ML) |

### Các payload test mẫu

```sql
-- Nên bị chặn (MALICIOUS)
' OR 1=1 --
UNION SELECT username, password FROM users --
'; DROP TABLE Events; --
CAST((SELECT password FROM users) AS int)
1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --
WAITFOR DELAY '0:0:5'--
admin'/**/OR/**/1=1--

-- Không nên bị chặn (BENIGN)
Tiệc cưới ngoài trời với view sông, menu 8 món, 120 khách
Tôi muốn đặt tiệc sinh nhật cho bé gái 8 tuổi, chủ đề công chúa
Teambuilding công ty ABC vào ngày 20/05/2026 tại Quận 7
```

### Xem Dashboard log

Đăng nhập Admin → truy cập: `https://localhost:44350/SQLInjectionLog`

Có thể lọc theo: **Tất cả / Rule-based / ML Model / Blocked**

---

## 🛠️ Khắc phục lỗi thường gặp

<details>
<summary><b>❌ Lỗi: <code>No module named flask</code></b></summary>

Chạy lại lệnh trong môi trường ảo đã activate:

```cmd
pip install flask pandas scikit-learn xgboost joblib numpy
```

</details>

<details>
<summary><b>❌ Lỗi: Không tìm thấy file <code>.pkl</code></b></summary>

Kiểm tra đã copy 2 file vào đúng thư mục:
```
eParty\wwwroot\models\sql_injection_xgboost_model.pkl
eParty\wwwroot\models\tfidf_vectorizer.pkl
```

</details>

<details>
<summary><b>❌ Lỗi: Website load mãi không ra (ML timeout)</b></summary>

Đảm bảo `app.py` đang chạy **trước khi** mở website. Kiểm tra CMD xem Flask đã hiện dòng:
```
🚀 SQL Injection Detection API đang chạy tại http://localhost:5000
```

Nếu Flask không chạy, hệ thống vẫn hoạt động bình thường (fallback cho qua) nhưng lớp ML bị tắt.

</details>

<details>
<summary><b>❌ Lỗi: Telegram không nhận tin nhắn</b></summary>

1. Kiểm tra bot token bằng cách truy cập:
   ```
   https://api.telegram.org/bot<TOKEN>/getMe
   ```
   Phải trả về `{"ok": true, ...}`

2. Xem **Output window** trong Visual Studio (Ctrl+Alt+O), tìm dòng `[Telegram]` để đọc lỗi chi tiết từ Telegram API.

3. Kiểm tra Output window có lỗi gì không — nếu thấy `TaskCanceledException` nghĩa là Flask timeout (xem mục trên).

</details>

<details>
<summary><b>❌ Lỗi: Nút Telegram bấm không có tác dụng</b></summary>

Webhook chưa được đăng ký hoặc ngrok đã đổi URL. Kiểm tra:
```
https://api.telegram.org/bot<TOKEN>/getWebhookInfo
```

Nếu `url` trống hoặc sai → đăng ký lại webhook (xem Bước 3 phần Chạy hệ thống).

</details>

<details>
<summary><b>❌ Lỗi: <code>Bad Request - Invalid Hostname</code> khi truy cập qua ngrok</b></summary>

IIS Express từ chối hostname ngrok. Mở file:
```
C:\Users\<TênBạn>\Documents\IISExpress\config\applicationhost.config
```

Tìm site eParty (port 44350) và thêm binding:
```xml
<binding protocol="https" bindingInformation="*:44350:" />
```

Hoặc dùng lệnh ngrok với `--host-header=rewrite`:
```cmd
ngrok http --host-header=rewrite https://localhost:44350
```

</details>

---

## 🔍 Chi tiết kỹ thuật

### Rule-based Filter

Sử dụng 2 cơ chế song song:

**Literal patterns** (so sánh chuỗi, O(n)):
```
or 1=1, union select, drop table, information_schema,
cast(, convert(, sleep(, benchmark(, @@version, xp_cmdshell, ...
```

**Regex patterns** (compiled, tái sử dụng):
```regex
cast\s*\(.+?as\s+int
union\s*/\*+\*/\s*select
0x[0-9a-f]{2,}
select\s+.+\s+from\s+\w+
;\s*(drop|delete|update|insert)\s+
...
```

### Normalize Input

Trước khi kiểm tra rule, input được chuẩn hóa:

1. **URL decode** nhiều lần (chống double encoding: `%2527` → `%27` → `'`)
2. **Strip SQL comments** `/*...*/` thay bằng rỗng (không phải space):
   - `SE/**/LECT` → `SELECT` ✅ (detect được)
   - `SE/**/ LECT` → `SE LECT` ❌ (nếu thay bằng space sẽ miss)
3. **Normalize whitespace**

### ML Model

| Thành phần | Chi tiết |
|-----------|---------|
| Thuật toán | XGBoost Classifier |
| Feature extraction | TF-IDF (char_wb, n-gram 1-3, max 5000 features) |
| Dataset | Modified SQL Injection Dataset |
| Threshold | `probability > 0.55` → chặn |
| Timeout | 1500ms (fallback: cho qua nếu Flask không phản hồi) |

### Dynamic Whitelist

Whitelist lưu trong bộ nhớ (in-memory `List<string>`), được nạp khi Admin phê duyệt qua Telegram. Không mất dữ liệu log vì log được lưu vào DB.

> ⚠️ **Lưu ý:** Dynamic whitelist sẽ reset khi restart IIS. Nếu cần persistent whitelist, cần lưu vào DB và load lại khi khởi động.

---

## 📊 Kết quả Model

| Metric | XGBoost | RandomForest |
|--------|---------|--------------|
| Accuracy (Test) | ~97% | ~95% |
| False Positive (Tiếng Việt) | Thấp (có whitelist) | Trung bình |
| Tốc độ inference | ~5ms | ~8ms |

---

## 🤝 Đóng góp

Nếu gặp lỗi hoặc muốn cải thiện, hãy mở [Issue](https://github.com/sangtran121/sql-injection-detection-ml/issues) kèm:
- Ảnh chụp màn hình lỗi
- Payload gây ra vấn đề
- Dòng log trong Output window của Visual Studio

---

<div align="center">

Được xây dựng trong môn học Lập trình Web — **Nhóm eParty** 🎉

</div>
