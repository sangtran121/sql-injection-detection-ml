using eParty.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
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
        public JsonResult TestBatch(string payloads)
        {
            if (string.IsNullOrWhiteSpace(payloads))
                return Json(new { success = false, message = "Không có payload" });

            var lines = payloads.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var results = new List<object>();

            using (var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) })
            {
                foreach (var line in lines)
                {
                    string payload = line.Trim();
                    if (string.IsNullOrWhiteSpace(payload)) continue;

                    bool isBlocked = false;
                    string reason = "An toàn";
                    double prob = 0;

                    try
                    {
                        var jsonContent = new StringContent(
                            Newtonsoft.Json.JsonConvert.SerializeObject(new { query = payload }),
                            Encoding.UTF8,
                            "application/json");

                        var response = client.PostAsync("http://localhost:5000/predict", jsonContent).Result;

                        if (response.IsSuccessStatusCode)
                        {
                            var resultJson = response.Content.ReadAsStringAsync().Result;
                            dynamic data = Newtonsoft.Json.JsonConvert.DeserializeObject(resultJson);

                            prob = Convert.ToDouble(data.probability ?? 0);
                            isBlocked = prob > 0.55;
                            reason = $"ML Model (Prob: {prob:F4})";
                        }
                        else
                        {
                            reason = $"Flask trả về lỗi {response.StatusCode}";
                        }
                    }
                    catch (Exception ex)
                    {
                        reason = $"Flask lỗi: {ex.Message}";
                        // Fallback Rule
                        string lower = payload.ToLower();
                        isBlocked = lower.Contains("union") || lower.Contains("or 1=1") ||
                                   lower.Contains("drop table") || lower.Contains("pg_sleep") ||
                                   lower.Contains("waitfor");
                    }

                    results.Add(new
                    {
                        Payload = payload.Length > 90 ? payload.Substring(0, 87) + "..." : payload,
                        Status = isBlocked ? "🚫 BỊ CHẶN" : "✅ Cho qua",
                        Reason = reason,
                        Probability = prob
                    });
                }
            }

            return Json(new { success = true, results, total = results.Count });
        }
    }
}