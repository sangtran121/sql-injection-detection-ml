using eParty.Helpers;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Web.Mvc;

namespace eParty.Controllers
{
    [Authorize(Roles = "Admin")]
    public class SqlInjectionTestController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public JsonResult TestBatch(string payloads, string mode = "ml")
        {
            if (string.IsNullOrWhiteSpace(payloads))
                return Json(new { success = false, message = "Không có payload" });

            var lines = payloads.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var results = new List<object>();
            var filter = new SqlInjectionFilter();

            foreach (var line in lines)
            {
                string payload = line.Trim();
                if (string.IsNullOrWhiteSpace(payload)) continue;

                bool isBlocked = false;
                string reason = "An toàn";
                double prob = 0;

                // [FIX] Normalize input giống hệt SqlInjectionFilter.OnActionExecuting
                // → decode URL encoding, loại /**/,  trước khi check
                // Nếu không normalize ở đây, kết quả test sẽ lệch với filter thật
                // [FIX] Check raw trước (giống OnActionExecuting): bắt /*! */ trước khi strip
                string rawLower = payload.ToLower();
                string normalizedPayload = filter.NormalizeInput(payload);
                string lower = normalizedPayload.ToLower().Trim();

                if (mode == "full")
                {
                    // Bước 0: check raw để bắt /*! pattern trước khi strip comment
                    if (filter.IsClearlyDangerous(rawLower))
                    {
                        isBlocked = true;
                        reason = "Full Filter - Rule-based chặn (raw)";
                    }
                    // Bước 1: check normalized
                    else if (filter.IsClearlyDangerous(lower))
                    {
                        isBlocked = true;
                        reason = "Full Filter - Rule-based chặn";
                    }
                    else if (filter.IsPureVietnameseText(lower))
                    {
                        isBlocked = false;
                        reason = "Full Filter - Text tiếng Việt an toàn";
                    }
                    else
                    {
                        prob = GetMLProbability(normalizedPayload);
                        isBlocked = prob > 0.55;
                        reason = isBlocked
                            ? $"Full Filter - ML chặn (prob={prob:F4})"
                            : $"Full Filter - ML cho qua (prob={prob:F4})";
                    }
                }
                else // mode = "ml"
                {
                    prob = GetMLProbability(normalizedPayload);
                    isBlocked = prob > 0.55;
                    reason = $"Only ML (prob={prob:F4})";
                }

                results.Add(new
                {
                    Payload = payload.Length > 90 ? payload.Substring(0, 87) + "..." : payload,
                    Status = isBlocked ? "🚫 BỊ CHẶN" : "✅ Cho qua",
                    Reason = reason,
                    Probability = prob,
                    TestMode = mode == "full" ? "Full Filter" : "Only ML"
                });
            }

            return Json(new { success = true, results, total = results.Count });
        }

        private double GetMLProbability(string query)
        {
            try
            {
                using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) })
                {
                    var content = new StringContent(
                        JsonConvert.SerializeObject(new { query = query }),
                        Encoding.UTF8,
                        "application/json");

                    var response = client.PostAsync("http://localhost:5000/predict", content).Result;

                    if (response.IsSuccessStatusCode)
                    {
                        var json = response.Content.ReadAsStringAsync().Result;
                        dynamic data = JsonConvert.DeserializeObject(json);
                        return Convert.ToDouble(data?.probability ?? 0);
                    }
                }
            }
            catch { }

            return 0;
        }
    }
}
