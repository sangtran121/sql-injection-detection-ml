using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace eParty.Helpers
{
    public class SqlInjectionFilter : ActionFilterAttribute
    {
        private static readonly string FlaskUrl = "http://localhost:5000/predict";
        private static readonly double MLThreshold = 0.55;

        // [CẢI THIỆN] Tăng timeout lên 1500ms để giảm false negative khi server bận
        private static readonly HttpClient client = new HttpClient
        {
            Timeout = TimeSpan.FromMilliseconds(1500)
        };

        private static readonly string[] VietnameseWhitelist = {
            "tiệc cưới", "tiệc sinh nhật", "menu", "khách mời", "ngoài trời", "chủ đề",
            "teambuilding", "buffet", "trang trí", "âm thanh", "mc", "band nhạc",
            "view sông", "món", "dự kiến", "công chúa", "sinh nhật bé", "khách",
            "tổng chi phí", "đặt tiệc", "teambuilding công ty"
        };

        // [CẢI THIỆN] Dùng static regex để tránh compile lại mỗi request (tăng hiệu suất)
        private static readonly Regex[] DangerousRegexPatterns = {
            new Regex(@"cast\s*\(.+?as\s+int", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"convert\s*\(\s*int", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"union\s*/\*+\*/\s*select", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"0x[0-9a-f]{2,}", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"%[0-9a-f]{2}", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"'[^']*'\s*=\s*'[^']*'", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"\bor\s+\d+=\d+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"\band\s+\d+=\d+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"select\s+.+\s+from\s+\w+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@";\s*(drop|delete|update|insert)\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        // [CẢI THIỆN] Tập trung patterns vào 1 chỗ, không hardcode lại ở method
        private static readonly string[] DangerousLiteralPatterns = {
            "or 1=1", "'1'='1", "admin' or", "1' or '1", "union select",
            "drop table", "pg_sleep", "waitfor delay", "xp_cmdshell",
            "information_schema", "/**/", "/*!",
            "cast(", "convert(", "sysobjects",
            "sys.databases", "sys.all_objects", "xtype='u'",
            "benchmark(", "sleep(",
            "; drop", "; delete", "; update",
            "master..sysdatabases", "master.sysdatabases",
            "net user", "ipconfig", "@@version", "@@servername",
            "char(", "nchar(", "varchar(",
        };

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            string controller = (filterContext.RouteData.Values["controller"]?.ToString() ?? "").ToLower();
            if (controller == "sqlinjectiontest")
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            string rawInput = GetAllInput(filterContext.HttpContext.Request);

            if (string.IsNullOrWhiteSpace(rawInput) || rawInput.Length < 5)
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            // [FIX] Bước 0: Check raw input (chưa strip comment) trước
            // Lý do: "Tiệc cưới đẹp' /*! OR 1=1 */ --"
            //   → Sau normalize: "Tiệc cưới đẹp' --" (/*! OR 1=1 */ bị strip)
            //   → IsClearlyDangerous không thấy gì → IsPureVietnameseText match → CHO QUA ❌
            //   → Phải check "/*!" trên raw input TRƯỚC KHI strip
            string rawLower = rawInput.ToLower();
            if (IsClearlyDangerous(rawLower))
            {
                LogToDatabase(filterContext, rawInput, "Rule-based (raw)");
                HandleSuspiciousRequest(filterContext);
                return;
            }

            // Normalize: decode URL encoding + strip SQL comments
            string normalizedInput = NormalizeInput(rawInput);
            string lower = normalizedInput.ToLower().Trim();

            // Lớp 1: Rule-based trên input đã normalize (bắt các pattern sau decode URL)
            if (IsClearlyDangerous(lower))
            {
                LogToDatabase(filterContext, rawInput, "Rule-based (normalized)");
                HandleSuspiciousRequest(filterContext);
                return;
            }

            // Lớp 2: Whitelist tiếng Việt — chỉ cho qua khi không còn gì nguy hiểm
            if (IsPureVietnameseText(lower))
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            // Lớp 3: ML Model (bất đồng bộ)
            // [CẢI THIỆN] Chạy ML check đồng bộ thay vì fire-and-forget
            // Fix race condition: bản cũ dùng Task.Run rồi base.OnActionExecuting ngay lập tức
            // → request vẫn đi qua dù ML phát hiện tấn công
            bool mlBlocked = CheckWithML(normalizedInput, filterContext);
            if (mlBlocked) return;

            base.OnActionExecuting(filterContext);
        }

        // [CẢI THIỆN] Normalize input để chống bypass bằng encoding
        public string NormalizeInput(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            string decoded = input;

            // Decode URL encoding nhiều lần (chống double encoding: %2527 → %27 → ')
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    string temp = HttpUtility.UrlDecode(decoded);
                    if (temp == decoded) break;
                    decoded = temp;
                }
                catch { break; }
            }

            // [FIX] Strip SQL comment /*...*/ KHÔNG thêm space
            // Lý do: "SE/**/LECT" → replace bằng " " ra "SE LECT" (không match)
            //                      → replace bằng ""  ra "SELECT"  (match đúng)
            // Regex này xử lý cả /**/, /*!50000...*/, /* bất kỳ nội dung */
            decoded = Regex.Replace(decoded, @"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/", "");

            // Normalize khoảng trắng thừa sau khi strip comment
            decoded = Regex.Replace(decoded, @"\s+", " ");

            return decoded.Trim();
        }

        // [CẢI THIỆN] Dùng DangerousLiteralPatterns[] thay vì hardcode lại
        public bool IsClearlyDangerous(string lower)
        {
            // Kiểm tra literal patterns từ mảng tập trung
            if (DangerousLiteralPatterns.Any(p => lower.Contains(p)))
                return true;

            // Kiểm tra regex patterns đã được compile sẵn
            if (DangerousRegexPatterns.Any(r => r.IsMatch(lower)))
                return true;

            return false;
        }

        public bool IsPureVietnameseText(string lower)
        {
            // Phải có từ tiếng Việt VÀ không có pattern nguy hiểm
            return VietnameseWhitelist.Any(w => lower.Contains(w)) &&
                   !IsClearlyDangerous(lower);
        }

        // [CẢI THIỆN] Đổi từ async fire-and-forget sang đồng bộ để chặn được request
        private bool CheckWithML(string query, ActionExecutingContext filterContext)
        {
            try
            {
                var payload = new { query = query };
                var content = new StringContent(
                    JsonConvert.SerializeObject(payload),
                    Encoding.UTF8,
                    "application/json"
                );

                // Chạy đồng bộ với timeout đã cấu hình trên HttpClient
                var response = client.PostAsync(FlaskUrl, content).GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode) return false;

                var resultJson = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                dynamic result = JsonConvert.DeserializeObject(resultJson);
                double probability = Convert.ToDouble(result?.probability ?? 0);

                if (probability > MLThreshold)
                {
                    LogToDatabase(filterContext, query, $"ML Model (prob={probability:F4})");
                    HandleSuspiciousRequest(filterContext);
                    return true; // Đã chặn
                }
            }
            catch (TaskCanceledException)
            {
                // Flask timeout → fallback, cho qua (không crash website)
            }
            catch
            {
                // Flask không chạy hoặc lỗi mạng → fallback, cho qua
            }

            return false;
        }

        private string GetAllInput(HttpRequestBase request)
        {
            var sb = new StringBuilder();

            if (request.Form != null)
                foreach (var key in request.Form.AllKeys ?? Array.Empty<string>())
                    sb.Append(' ').Append(request.Form[key]);

            if (request.QueryString != null)
                foreach (var key in request.QueryString.AllKeys ?? Array.Empty<string>())
                    sb.Append(' ').Append(request.QueryString[key]);

            sb.Append(' ').Append(request.RawUrl ?? "");

            return sb.ToString().Trim();
        }

        private void LogToDatabase(ActionExecutingContext filterContext, string payload, string detectedBy)
        {
            try
            {
                using (var db = new AppDbContext())
                {
                    var log = new SQLInjectionLog
                    {
                        Timestamp = DateTime.Now,
                        IpAddress = filterContext.HttpContext.Request.UserHostAddress ?? "::1",
                        Url = filterContext.HttpContext.Request.RawUrl,
                        // [CẢI THIỆN] Lưu thêm DetectedBy để dễ phân tích sau
                        SuspiciousInput = (payload.Length > 500
                            ? payload.Substring(0, 500) + "..."
                            : payload) + $" [Detected by: {detectedBy}]",
                        Controller = filterContext.RouteData.Values["controller"]?.ToString() ?? "Unknown",
                        Action = filterContext.RouteData.Values["action"]?.ToString() ?? "Unknown",
                        UserAgent = filterContext.HttpContext.Request.UserAgent,
                        IsBlocked = true
                    };
                    db.SQLInjectionLogs.Add(log);
                    db.SaveChanges();
                }
            }
            catch { /* Không để lỗi log crash website */ }
        }

        private void HandleSuspiciousRequest(ActionExecutingContext filterContext)
        {
            filterContext.HttpContext.Response.StatusCode = 403;
            filterContext.Result = new JsonResult
            {
                Data = new
                {
                    success = false,
                    message = "Yêu cầu bị chặn vì nghi ngờ SQL Injection!",
                    code = "SQL_INJECTION_DETECTED"
                },
                JsonRequestBehavior = JsonRequestBehavior.AllowGet
            };
        }
    }
}
