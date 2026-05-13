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

        private static readonly HttpClient client = new HttpClient
        {
            Timeout = TimeSpan.FromMilliseconds(700)
        };

        private static readonly string[] VietnameseWhitelist = {
            "tiệc cưới", "tiệc sinh nhật", "menu", "khách mời", "ngoài trời", "chủ đề",
            "teambuilding", "buffet", "trang trí", "âm thanh", "MC", "band nhạc",
            "view sông", "món", "dự kiến", "công chúa", "sinh nhật bé", "khách",
            "tổng chi phí", "đặt tiệc", "teambuilding công ty"
        };

        // ================== RULE ĐÃ CẬP NHẬT MẠNH HƠN ==================
        private static readonly string[] DangerousPatterns = {
            "or 1=1", "'1'='1", "admin' or", "1' or '1", "union select",
            "drop table", "pg_sleep", "waitfor delay", "xp_cmdshell",
            "information_schema", "cast\\(", "convert\\(",
            "sysobjects", "sys\\.databases", "sys\\.all_objects", "xtype='U'",
            "information_schema\\.columns", "information_schema\\.routines",
            "0x", "/**/", "/*! ", "; drop", "; delete", "; update",
            "benchmark\\(", "sleep\\(", "master\\.sysdatabases"
        };

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            string controller = (filterContext.RouteData.Values["controller"]?.ToString() ?? "").ToLower();
            if (controller == "sqlinjectiontest")
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            string input = GetAllInput(filterContext.HttpContext.Request);

            if (string.IsNullOrWhiteSpace(input) || input.Length < 5)
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            string lower = input.ToLower().Trim();

            if (IsClearlyDangerous(lower))
            {
                LogToDatabase(filterContext, input, "Rule-based");
                HandleSuspiciousRequest(filterContext);
                return;
            }

            if (IsPureVietnameseText(lower))
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            Task.Run(async () => await CheckWithMLAsync(input, filterContext));

            base.OnActionExecuting(filterContext);
        }

        // Hai hàm public để Test Controller gọi được
        public bool IsPureVietnameseText(string lower)
        {
            return VietnameseWhitelist.Any(w => lower.Contains(w)) &&
                   !DangerousPatterns.Any(p => lower.Contains(p));
        }

        public bool IsClearlyDangerous(string lower)
        {
            // Dùng Contains cho các pattern literal (an toàn và nhanh)
            if (lower.Contains("or 1=1") ||
                lower.Contains("'1'='1") ||
                lower.Contains("admin' or") ||
                lower.Contains("1' or '1") ||
                lower.Contains("union select") ||
                lower.Contains("drop table") ||
                lower.Contains("pg_sleep") ||
                lower.Contains("waitfor delay") ||
                lower.Contains("xp_cmdshell") ||
                lower.Contains("information_schema") ||
                lower.Contains("/**/") ||           // ← Sửa lỗi ở đây
                lower.Contains("/*!") ||
                lower.Contains("cast((select") ||
                lower.Contains("0x") ||
                lower.Contains("benchmark(") ||
                lower.Contains("sleep(") ||
                lower.Contains("; drop") ||
                lower.Contains("; delete") ||
                lower.Contains("; update"))
            {
                return true;
            }

            // Regex chỉ dùng cho pattern phức tạp
            var regexPatterns = new[]
            {
        @"cast\(.+as int",
        @"convert\(.+as int",
        @"sysobjects",
        @"sys\.databases",
        @"sys\.all_objects",
        @"xtype='U'",
        @"union\s*/\*\*/\s*select"
    };

            return regexPatterns.Any(p => Regex.IsMatch(lower, p, RegexOptions.IgnoreCase));
        }

        private string GetAllInput(HttpRequestBase request)
        {
            string all = "";
            if (request.Form != null)
                foreach (var key in request.Form.AllKeys ?? Array.Empty<string>())
                    all += " " + request.Form[key];
            if (request.QueryString != null)
                foreach (var key in request.QueryString.AllKeys ?? Array.Empty<string>())
                    all += " " + request.QueryString[key];
            all += " " + (request.RawUrl ?? "");
            return all.Trim();
        }

        private async Task CheckWithMLAsync(string query, ActionExecutingContext context)
        {
            try
            {
                var payload = new { query = query };
                var content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json");
                var response = await client.PostAsync(FlaskUrl, content);
                if (!response.IsSuccessStatusCode) return;

                var resultJson = await response.Content.ReadAsStringAsync();
                dynamic result = JsonConvert.DeserializeObject(resultJson);
                double probability = Convert.ToDouble(result.probability ?? 0);

                if (probability > MLThreshold)
                {
                    LogToDatabase(context, query, $"ML Model ({probability:F4})");
                }
            }
            catch { }
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
                        SuspiciousInput = payload.Length > 500 ? payload.Substring(0, 500) + "..." : payload,
                        Controller = filterContext.RouteData.Values["controller"]?.ToString() ?? "Unknown",
                        Action = filterContext.RouteData.Values["action"]?.ToString() ?? "Unknown",
                        UserAgent = filterContext.HttpContext.Request.UserAgent,
                        IsBlocked = true
                    };
                    db.SQLInjectionLogs.Add(log);
                    db.SaveChanges();
                }
            }
            catch { }
        }

        private void HandleSuspiciousRequest(ActionExecutingContext filterContext)
        {
            filterContext.Result = new JsonResult
            {
                Data = new { success = false, message = "Yêu cầu bị chặn vì nghi ngờ SQL Injection!", code = "SQL_INJECTION_DETECTED" },
                JsonRequestBehavior = JsonRequestBehavior.AllowGet
            };
            filterContext.HttpContext.Response.StatusCode = 403;
        }
    }
}