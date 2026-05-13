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

        private static readonly string[] DangerousPatterns = {
            "or 1=1", "'1'='1", "admin' or", "1' or '1", "union select",
            "drop table", "pg_sleep", "waitfor delay", "xp_cmdshell",
            "information_schema", "cast((select", "0x", "/**/", "/*! ",
            "; drop", "; delete", "; update", "benchmark(", "sleep("
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

            // 1. Rule-based mạnh hơn (ưu tiên cao)
            if (IsClearlyDangerous(lower))
            {
                LogToDatabase(filterContext, input, "Rule-based");
                HandleSuspiciousRequest(filterContext);
                return;
            }

            // 2. Text thuần Việt thuần túy (không lẫn payload) → Cho qua
            if (IsPureVietnameseText(lower))
            {
                base.OnActionExecuting(filterContext);
                return;
            }

            // 3. Gọi ML Model (nếu Flask đang chạy)
            Task.Run(async () => await CheckWithMLAsync(input, filterContext));

            base.OnActionExecuting(filterContext);
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

        private bool IsPureVietnameseText(string lower)
        {
            return VietnameseWhitelist.Any(w => lower.Contains(w)) &&
                   !DangerousPatterns.Any(p => lower.Contains(p));
        }

        private bool IsClearlyDangerous(string lower)
        {
            // Pattern mở rộng
            var strongPatterns = new[]
            {
        "or 1=1", "'1'='1", "union select", "drop table", "pg_sleep",
        "waitfor delay", "xp_cmdshell", "information_schema", "/\\*\\*/",
        "/\\*!", "cast\\(.+as int", "0x", "benchmark\\(", "sleep\\(",
        "admin' or", "1' or '1", ";\\s*drop", ";\\s*delete", "union\\s+/\\*\\*/select"
            };

            return strongPatterns.Any(p =>
                Regex.IsMatch(lower, p, RegexOptions.IgnoreCase) ||
                lower.Contains(p.Replace("\\", "")));
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
                    // Không chặn request đã chạy, chỉ log để sau này review
                }
            }
            catch (Exception ex)
            {
                // Flask lỗi hoặc chưa chạy → ghi log để debug
                System.Diagnostics.Debug.WriteLine($"Flask ML Error: {ex.Message}");
            }
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