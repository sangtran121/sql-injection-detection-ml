using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace eParty.Helpers
{
    public class SqlInjectionFilter : ActionFilterAttribute
    {
        private static readonly string NewFlaskUrl = "http://127.0.0.1:5010/predict";
        private static readonly string OldFlaskUrl = "http://127.0.0.1:5000/predict";

        // Dùng chung HttpClient, timeout ngắn để không làm treo website
        private static readonly HttpClient client = new HttpClient
        {
            Timeout = TimeSpan.FromMilliseconds(1500)
        };
        private class SqlInjectionMlDecision
        {
            public bool IsSqlInjection { get; set; }
            public double Probability { get; set; }
            public double RawProbability { get; set; }
            public double Threshold { get; set; }
            public string Status { get; set; }
            public string Model { get; set; }
            public string DecisionSource { get; set; }
            public string ApiSource { get; set; }
        }

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
            var controllerName = filterContext.ActionDescriptor.ControllerDescriptor.ControllerName;
            

            // Bỏ qua trang test so sánh model SQL Injection trong Admin.
            // Nếu không bỏ qua, payload như admin' OR 1=1 -- sẽ bị filter chặn trước khi vào controller test.
            if (controllerName.Equals("SqlInjectionModelComparison", StringComparison.OrdinalIgnoreCase))
            {
                base.OnActionExecuting(filterContext);
                return;
            }
            string controller = (filterContext.RouteData.Values["controller"]?.ToString() ?? "").ToLowerInvariant();
            string action = (filterContext.RouteData.Values["action"]?.ToString() ?? "").ToLowerInvariant();

            // BYPASS FILTER - Cho phép ReportFalsePositive và Test
            if ((controller == "sqlinjectionlog" && action == "reportfalsepositive") ||
                controller == "sqlinjectiontest")
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

            // ================== WHITELIST ĐỘNG - Ưu tiên cao nhất ==================
            if (IsInDynamicWhitelist(rawInput))
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            // [FIX] Bước 0: Check raw input (chưa strip comment) trước
            string rawLower = rawInput.ToLower();
            //if (IsClearlyDangerous(rawLower))
            //{
            //    string detectedBy = "Rule-based (raw)";
            //    LogToDatabase(filterContext, rawInput, detectedBy);
            //    HandleSuspiciousRequest(filterContext, detectedBy);
            //    return;
            //}

            // Normalize input
            string normalizedInput = NormalizeInput(rawInput);
            string lower = normalizedInput.ToLower().Trim();

            // Lớp 1: Rule-based trên normalized input
            //if (IsClearlyDangerous(lower))
            //{
            //    string detectedBy = "Rule-based (normalized)";
            //    LogToDatabase(filterContext, rawInput, detectedBy);
            //    HandleSuspiciousRequest(filterContext, detectedBy);
            //    return;
            //}

            // Lớp 2: Whitelist tiếng Việt
            if (IsPureVietnameseText(lower))
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            // Lớp 3: ML Model
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
            SqlInjectionMlDecision decision = null;

            // 1. Ưu tiên model mới Stacking Ensemble ở port 5010
            decision = CallSqlInjectionApi(NewFlaskUrl, query, "Stacking_5010");

            // 2. Nếu 5010 sập / timeout / lỗi HTTP thì fallback sang model cũ XGBoost 5000
            if (decision == null)
            {
                decision = CallSqlInjectionApi(OldFlaskUrl, query, "XGBoost_5000_Fallback");
            }

            // 3. Nếu cả hai API đều lỗi thì cho request đi tiếp để web không bị đứng
            if (decision == null)
            {
                return false;
            }

            // 4. Không tự so threshold ở C# nữa.
            // Python API đã quyết định is_sql_injection theo threshold riêng của từng model.
            if (decision.IsSqlInjection)
            {
                string detectedBy =
                    $"ML {decision.ApiSource} | model={decision.Model} | prob={decision.Probability:F4} | threshold={decision.Threshold:F4} | source={decision.DecisionSource}";

                LogToDatabase(filterContext, query, detectedBy);

                HandleSuspiciousRequest(filterContext, detectedBy);
                return true;
            }

            return false;
        }
        private SqlInjectionMlDecision CallSqlInjectionApi(string apiUrl, string query, string apiSource)
        {
            try
            {
                var payload = new
                {
                    query = query
                };

                using (var content = new StringContent(
                    JsonConvert.SerializeObject(payload),
                    Encoding.UTF8,
                    "application/json"))
                {
                    var response = client.PostAsync(apiUrl, content).GetAwaiter().GetResult();

                    if (!response.IsSuccessStatusCode)
                    {
                        return null;
                    }

                    var resultJson = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    var obj = Newtonsoft.Json.Linq.JObject.Parse(resultJson);

                    bool isSqlInjection = obj["is_sql_injection"] != null
                        ? obj.Value<bool>("is_sql_injection")
                        : false;

                    double probability = obj["probability"] != null
                        ? obj.Value<double>("probability")
                        : 0;

                    double rawProbability = obj["raw_probability"] != null
                        ? obj.Value<double>("raw_probability")
                        : probability;

                    double threshold = obj["threshold"] != null
                        ? obj.Value<double>("threshold")
                        : (apiSource.Contains("5000") ? 0.52 : 0);

                    string status = obj["status"] != null
                        ? obj.Value<string>("status")
                        : "";

                    string model = obj["model"] != null
                        ? obj.Value<string>("model")
                        : apiSource;

                    string decisionSource = obj["decision_source"] != null
                        ? obj.Value<string>("decision_source")
                        : apiSource;

                    return new SqlInjectionMlDecision
                    {
                        IsSqlInjection = isSqlInjection,
                        Probability = probability,
                        RawProbability = rawProbability,
                        Threshold = threshold,
                        Status = status,
                        Model = model,
                        DecisionSource = decisionSource,
                        ApiSource = apiSource
                    };
                }
            }
            catch
            {
                return null;
            }
        }

        private string GetAllInput(HttpRequestBase request)
        {
            var sb = new StringBuilder();

            try
            {
                var unvalidated = request.Unvalidated;

                if (unvalidated.Form != null)
                {
                    foreach (var key in unvalidated.Form.AllKeys ?? Array.Empty<string>())
                    {
                        if (!string.IsNullOrWhiteSpace(key))
                            sb.Append(' ').Append(key);

                        var value = unvalidated.Form[key];
                        if (!string.IsNullOrWhiteSpace(value))
                            sb.Append(' ').Append(value);
                    }
                }

                if (unvalidated.QueryString != null)
                {
                    foreach (var key in unvalidated.QueryString.AllKeys ?? Array.Empty<string>())
                    {
                        if (!string.IsNullOrWhiteSpace(key))
                            sb.Append(' ').Append(key);

                        var value = unvalidated.QueryString[key];
                        if (!string.IsNullOrWhiteSpace(value))
                            sb.Append(' ').Append(value);
                    }
                }

                sb.Append(' ').Append(request.RawUrl ?? "");
            }
            catch
            {
                return request.RawUrl ?? "";
            }

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

 
        // ================== WHITELIST ĐỘNG (từ Dashboard) ==================
        private static readonly List<string> DynamicWhitelist = new List<string>();

        public static void AddToWhitelist(string payload)
        {
            if (string.IsNullOrWhiteSpace(payload)) return;
            string clean = payload.Trim();
            if (!DynamicWhitelist.Contains(clean))
            {
                DynamicWhitelist.Add(clean);
                System.Diagnostics.Debug.WriteLine($"[WHITELIST] Đã thêm: {clean}");
            }
        }

        public static void ClearDynamicWhitelist()
        {
            DynamicWhitelist.Clear();
        }

        private bool IsInDynamicWhitelist(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return false;
            string lower = input.ToLower().Trim();
            return DynamicWhitelist.Any(w => lower.Contains(w.ToLower()));
        }
        private void HandleSuspiciousRequest(ActionExecutingContext filterContext, string detectedBy)
        {
            var request = filterContext.HttpContext.Request;
            string suspiciousInput = GetAllInput(request);
            string returnUrl = request.RawUrl;
            string method = request.HttpMethod;

            // Serialize form data để replay sau khi whitelist
            var formDict = new System.Collections.Generic.Dictionary<string, string>();
            try
            {
                var unvalidatedForm = request.Unvalidated.Form;

                if (unvalidatedForm != null)
                {
                    foreach (var key in unvalidatedForm.AllKeys ?? new string[0])
                    {
                        formDict[key] = unvalidatedForm[key];
                    }
                }
            }
            catch
            {
                // Bỏ qua nếu không đọc được form
            }

            string formDataJson = Newtonsoft.Json.JsonConvert.SerializeObject(formDict);

            string token = SavePendingToken(suspiciousInput, returnUrl);

            filterContext.HttpContext.Response.StatusCode = 403;
            filterContext.Result = new ViewResult
            {
                ViewName = "~/Views/Shared/SQLInjectionBlocked.cshtml",
                ViewData = new ViewDataDictionary
        {
            { "SuspiciousInput", suspiciousInput },
            { "DetectedBy", detectedBy },
            { "Token",     token       },
            { "ReturnUrl", returnUrl   },
            { "Method",    method      },
            { "FormData",  formDataJson }
        }
            };
        }

        private string SavePendingToken(string payload, string returnUrl)
        {
            try
            {
                string token = Guid.NewGuid().ToString("N").Substring(0, 12);
                using (var db = new AppDbContext())
                {
                    db.PendingWhitelists.Add(new PendingWhitelist
                    {
                        Payload = payload,
                        Token = token,
                        ReturnUrl = returnUrl,
                        CreatedAt = DateTime.Now,
                        IsUsed = false
                    });
                    db.SaveChanges();
                }
                return token;
            }
            catch { return ""; }
        }
    }
}
