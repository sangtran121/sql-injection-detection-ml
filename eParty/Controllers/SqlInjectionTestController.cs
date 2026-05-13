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

                string lower = payload.ToLower().Trim();

                if (mode == "full") // ← Test y chang Filter thật trên web
                {
                    if (filter.IsPureVietnameseText(lower))
                    {
                        isBlocked = false;
                        reason = "Full Filter - Text tiếng Việt an toàn";
                    }
                    else if (filter.IsClearlyDangerous(lower))
                    {
                        isBlocked = true;
                        reason = "Full Filter - Rule-based chặn";
                    }
                    else
                    {
                        prob = GetMLProbability(payload);
                        isBlocked = prob > 0.55;
                        reason = $"Full Filter - ML Prob: {prob:F4}";
                    }
                }
                else // mode = "ml" (chỉ ML như trước)
                {
                    prob = GetMLProbability(payload);
                    isBlocked = prob > 0.55;
                    reason = $"Only ML (Prob: {prob:F4})";
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
                        Encoding.UTF8, "application/json");

                    var response = client.PostAsync("http://localhost:5000/predict", content).Result;

                    if (response.IsSuccessStatusCode)
                    {
                        var json = response.Content.ReadAsStringAsync().Result;
                        dynamic data = JsonConvert.DeserializeObject(json);
                        return Convert.ToDouble(data.probability ?? 0);
                    }
                }
            }
            catch { }
            return 0;
        }
    }
}