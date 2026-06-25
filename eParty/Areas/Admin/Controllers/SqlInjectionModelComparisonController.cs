using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace eParty.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class SqlInjectionModelComparisonController : Controller
    {
        private const string OldModelEndpoint = "http://127.0.0.1:5000/predict";
        private const string NewModelEndpoint = "http://127.0.0.1:5010/predict";

        public ActionResult Index()
        {
            var samples = GetSamples();

            var model = new SqlInjectionComparisonViewModel
            {
                Query = string.Join(Environment.NewLine, samples),
                Samples = samples,
                Rows = new List<SqlPayloadComparisonRow>(),
                HasResult = false
            };

            return View(model);
        }

        [HttpPost]
        [ActionName("Index")]
        [ValidateAntiForgeryToken]
        [ValidateInput(false)]
        public async Task<ActionResult> IndexPost()
        {
            var model = new SqlInjectionComparisonViewModel
            {
                Samples = GetSamples(),
                Rows = new List<SqlPayloadComparisonRow>()
            };

            string rawInput = Request.Unvalidated.Form["Query"];
            model.Query = rawInput;

            if (string.IsNullOrWhiteSpace(rawInput))
            {
                ModelState.AddModelError("Query", "Vui lòng nhập ít nhất một payload cần test.");
                return View(model);
            }

            var payloads = rawInput
                .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();

            int index = 1;

            foreach (var payload in payloads)
            {
                var oldResult = await CallSqlModelAsync(
                    OldModelEndpoint,
                    "XGBoost cũ",
                    "old_xgboost_5000",
                    payload
                );

                var newResult = await CallSqlModelAsync(
                    NewModelEndpoint,
                    "Stacking Ensemble mới",
                    "stacking_5010",
                    payload
                );

                model.Rows.Add(new SqlPayloadComparisonRow
                {
                    No = index++,
                    Query = payload,
                    OldResult = oldResult,
                    NewResult = newResult
                });
            }

            model.HasResult = true;

            return View(model);
        }

        private async Task<SqlModelTestResult> CallSqlModelAsync(
            string endpoint,
            string modelName,
            string sourceName,
            string query)
        {
            var result = new SqlModelTestResult
            {
                Endpoint = endpoint,
                ModelName = modelName,
                SourceName = sourceName,
                IsAvailable = false
            };

            var sw = Stopwatch.StartNew();

            try
            {
                using (var client = new HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(5);

                    var payload = new
                    {
                        query = query
                    };

                    string jsonPayload = JsonConvert.SerializeObject(payload);

                    using (var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json"))
                    {
                        var response = await client.PostAsync(endpoint, content);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        sw.Stop();

                        result.ResponseTimeMs = sw.Elapsed.TotalMilliseconds;
                        result.HttpStatusCode = (int)response.StatusCode;
                        result.RawJson = responseBody;

                        if (!response.IsSuccessStatusCode)
                        {
                            result.Error = "HTTP " + (int)response.StatusCode + ": " + responseBody;
                            return result;
                        }

                        var obj = JObject.Parse(responseBody);

                        result.IsAvailable = true;
                        result.IsSqlInjection = obj.Value<bool?>("is_sql_injection");
                        result.Probability = obj.Value<double?>("probability");
                        result.RawProbability = obj.Value<double?>("raw_probability");
                        result.Status = obj.Value<string>("status");
                        result.ModelFromApi = obj.Value<string>("model");
                        result.DecisionSource = obj.Value<string>("decision_source");
                        result.Threshold = obj.Value<double?>("threshold");
                        result.FlaskResponseTimeMs = obj.Value<double?>("response_time_ms");
                        result.MetaModel = obj.Value<string>("meta_model");

                        var baseScoresToken = obj["base_model_scores"] as JObject;
                        if (baseScoresToken != null)
                        {
                            result.BaseModelScores = baseScoresToken.Properties()
                                .ToDictionary(
                                    p => p.Name,
                                    p => p.Value.Type == JTokenType.Null
                                        ? (double?)null
                                        : p.Value.Value<double?>()
                                );
                        }

                        return result;
                    }
                }
            }
            catch (TaskCanceledException)
            {
                sw.Stop();
                result.ResponseTimeMs = sw.Elapsed.TotalMilliseconds;
                result.Error = "Timeout: endpoint không phản hồi trong 5 giây.";
                return result;
            }
            catch (Exception ex)
            {
                sw.Stop();
                result.ResponseTimeMs = sw.Elapsed.TotalMilliseconds;
                result.Error = ex.Message;
                return result;
            }
        }

        private List<string> GetSamples()
        {
            return new List<string>
            {
                "admin' OR 1=1 --",
                "UNION SELECT username, password FROM users --",
                "SELECT * FROM information_schema.tables",
                "CAST((SELECT password FROM users) AS int)",
                "WAITFOR DELAY '0:0:5'--",
                "Tôi muốn đặt tiệc cưới ngoài trời cho 120 khách",
                "Menu gồm gỏi cuốn, cá kho tộ và thịt nướng",
                "SELECT * FROM Events WHERE EventID = 42"
            };
        }
    }

    public class SqlPayloadComparisonRow
    {
        public int No { get; set; }
        public string Query { get; set; }
        public SqlModelTestResult OldResult { get; set; }
        public SqlModelTestResult NewResult { get; set; }
    }

    public class SqlInjectionComparisonViewModel
    {
        [AllowHtml]
        public string Query { get; set; }

        public bool HasResult { get; set; }

        // Giữ lại để không lỗi nếu View cũ còn dùng
        public SqlModelTestResult OldResult { get; set; }
        public SqlModelTestResult NewResult { get; set; }

        // Dùng cho test nhiều payload
        public List<SqlPayloadComparisonRow> Rows { get; set; }

        public List<string> Samples { get; set; }
    }

    public class SqlModelTestResult
    {
        public string Endpoint { get; set; }
        public string ModelName { get; set; }
        public string SourceName { get; set; }

        public bool IsAvailable { get; set; }
        public int HttpStatusCode { get; set; }

        public bool? IsSqlInjection { get; set; }
        public double? Probability { get; set; }
        public double? RawProbability { get; set; }
        public double? Threshold { get; set; }

        public string Status { get; set; }
        public string ModelFromApi { get; set; }
        public string DecisionSource { get; set; }
        public Dictionary<string, double?> BaseModelScores { get; set; }
        public string MetaModel { get; set; }

        public double ResponseTimeMs { get; set; }
        public double? FlaskResponseTimeMs { get; set; }

        public string RawJson { get; set; }
        public string Error { get; set; }
    }
}