
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace eParty.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class ApiGatewayModelComparisonController : Controller
    {
        private static readonly HttpClient Client = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(8)
        };

        private const string OldUrl = "http://127.0.0.1:5001/predict-api-gateway-ml-only";
        private const string NewUrl = "http://127.0.0.1:5011/predict-api-gateway-ml-only";

        [HttpGet]
        public ActionResult Index()
        {
            var model = new ApiGatewayComparisonViewModel();
            model.JsonPayloads = BuildDefaultPayloadText();
            model.Samples = BuildSamples();
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Index(ApiGatewayComparisonViewModel model)
        {
            if (model == null)
            {
                model = new ApiGatewayComparisonViewModel();
            }

            model.Samples = BuildSamples();

            if (string.IsNullOrWhiteSpace(model.JsonPayloads))
            {
                model.JsonPayloads = BuildDefaultPayloadText();
            }

            List<ApiGatewayComparisonInput> inputs = ParseInputLines(model.JsonPayloads);

            if (!inputs.Any())
            {
                ModelState.AddModelError("JsonPayloads", "Không có payload hợp lệ. Mỗi dòng phải là một JSON object.");
                return View(model);
            }

            model.Rows = new List<ApiGatewayComparisonRow>();

            foreach (var input in inputs)
            {
                var oldResultTask = CallModelAsync(OldUrl, input.JsonPayload, "Old 5001");
                var newResultTask = CallModelAsync(NewUrl, input.JsonPayload, "New 5011");

                await Task.WhenAll(oldResultTask, newResultTask).ConfigureAwait(false);

                var oldResult = oldResultTask.Result;
                var newResult = newResultTask.Result;

                var row = new ApiGatewayComparisonRow
                {
                    Name = input.Name,
                    ExpectedLabel = input.ExpectedLabel,
                    JsonPayload = input.JsonPayload,
                    OldResult = oldResult,
                    NewResult = newResult
                };

                row.OldCorrect = IsCorrect(oldResult, input.ExpectedLabel);
                row.NewCorrect = IsCorrect(newResult, input.ExpectedLabel);
                row.ScoreDifference = Math.Round(newResult.MlRiskScore - oldResult.MlRiskScore, 4);
                row.LabelChanged = !string.Equals(
                    oldResult.PredictedLabel,
                    newResult.PredictedLabel,
                    StringComparison.OrdinalIgnoreCase
                );

                model.Rows.Add(row);
            }

            model.HasResult = true;
            model.Summary = BuildSummary(model.Rows);

            return View(model);
        }

        private async Task<ApiGatewayComparisonResult> CallModelAsync(string url, string jsonPayload, string displayName)
        {
            var result = new ApiGatewayComparisonResult
            {
                DisplayName = displayName,
                IsOnline = false,
                PredictedLabel = "error",
                DecisionSource = "connection_error",
                ModelName = displayName
            };

            try
            {
                using (var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json"))
                {
                    var sw = Stopwatch.StartNew();

                    HttpResponseMessage response = await Client
                        .PostAsync(url, content)
                        .ConfigureAwait(false);

                    string responseText = await response.Content
                        .ReadAsStringAsync()
                        .ConfigureAwait(false);

                    sw.Stop();

                    if (!response.IsSuccessStatusCode)
                    {
                        result.ErrorMessage = "HTTP " + (int)response.StatusCode + ": " + responseText;
                        result.ResponseTimeMs = sw.Elapsed.TotalMilliseconds;
                        return result;
                    }

                    JObject obj = JObject.Parse(responseText);

                    result.IsOnline = true;
                    result.RawJson = responseText;
                    result.ModelName = ReadString(obj, "model", displayName);
                    result.PredictedLabel = ReadString(obj, "predicted_label", "unknown");
                    result.IsAbnormal = ReadBool(obj, "is_abnormal", false);
                    result.RiskScore = ReadDouble(obj, "risk_score", 0);
                    result.MlRiskScore = ReadDouble(obj, "ml_risk_score", result.RiskScore);
                    result.AttackScore = ReadDouble(obj, "attack_score", result.MlRiskScore);
                    result.NormalScore = ReadDouble(obj, "normal_score", 1 - result.MlRiskScore);
                    result.Threshold = ReadDouble(obj, "threshold", 0);
                    result.ResponseTimeMs = ReadDouble(obj, "response_time_ms", sw.Elapsed.TotalMilliseconds);
                    result.DecisionSource = ReadString(obj, "decision_source", "ml_only");
                    result.MetaModel = ReadString(obj, "meta_model", "");
                    result.Action = ReadString(obj, "action", "ml_only");
                    result.BaseModelScores = FormatBaseModelScores(obj["base_model_scores"]);

                    return result;
                }
            }
            catch (Exception ex)
            {
                result.ErrorMessage = ex.Message;
                return result;
            }
        }

        private bool IsCorrect(ApiGatewayComparisonResult result, string expectedLabel)
        {
            if (result == null || !result.IsOnline)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(expectedLabel) || expectedLabel == "unknown")
            {
                return false;
            }

            return string.Equals(
                result.PredictedLabel,
                expectedLabel,
                StringComparison.OrdinalIgnoreCase
            );
        }

        private ApiGatewayComparisonSummary BuildSummary(List<ApiGatewayComparisonRow> rows)
        {
            var summary = new ApiGatewayComparisonSummary();

            if (rows == null || rows.Count == 0)
            {
                return summary;
            }

            summary.Total = rows.Count;
            summary.OldOnline = rows.Count(x => x.OldResult != null && x.OldResult.IsOnline);
            summary.NewOnline = rows.Count(x => x.NewResult != null && x.NewResult.IsOnline);
            summary.OldCorrect = rows.Count(x => x.OldCorrect);
            summary.NewCorrect = rows.Count(x => x.NewCorrect);
            summary.LabelChanged = rows.Count(x => x.LabelChanged);

            summary.OldAvgRisk = Math.Round(rows.Where(x => x.OldResult != null && x.OldResult.IsOnline)
                .Select(x => x.OldResult.MlRiskScore)
                .DefaultIfEmpty(0)
                .Average(), 4);

            summary.NewAvgRisk = Math.Round(rows.Where(x => x.NewResult != null && x.NewResult.IsOnline)
                .Select(x => x.NewResult.MlRiskScore)
                .DefaultIfEmpty(0)
                .Average(), 4);

            summary.OldAvgTimeMs = Math.Round(rows.Where(x => x.OldResult != null && x.OldResult.IsOnline)
                .Select(x => x.OldResult.ResponseTimeMs)
                .DefaultIfEmpty(0)
                .Average(), 2);

            summary.NewAvgTimeMs = Math.Round(rows.Where(x => x.NewResult != null && x.NewResult.IsOnline)
                .Select(x => x.NewResult.ResponseTimeMs)
                .DefaultIfEmpty(0)
                .Average(), 2);

            return summary;
        }

        private List<ApiGatewayComparisonInput> ParseInputLines(string text)
        {
            var result = new List<ApiGatewayComparisonInput>();

            if (string.IsNullOrWhiteSpace(text))
            {
                return result;
            }

            string[] lines = text
                .Replace("\r\n", "\n")
                .Split('\n');

            int index = 1;

            foreach (string rawLine in lines)
            {
                string line = (rawLine ?? "").Trim();

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    JObject obj = JObject.Parse(line);

                    string name = ReadString(obj, "case_name", "Case " + index);
                    string expected = ReadString(obj, "expected_label", "unknown").ToLowerInvariant();

                    result.Add(new ApiGatewayComparisonInput
                    {
                        Name = name,
                        ExpectedLabel = expected,
                        JsonPayload = obj.ToString(Formatting.None)
                    });

                    index++;
                }
                catch
                {
                    // Bỏ qua dòng JSON lỗi để trang không crash.
                }
            }

            return result;
        }

        private static string ReadString(JObject obj, string name, string fallback)
        {
            if (obj == null || obj[name] == null || obj[name].Type == JTokenType.Null)
            {
                return fallback;
            }

            string value = obj[name].ToString();

            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }

            return value;
        }

        private static bool ReadBool(JObject obj, string name, bool fallback)
        {
            if (obj == null || obj[name] == null)
            {
                return fallback;
            }

            bool value;

            if (bool.TryParse(obj[name].ToString(), out value))
            {
                return value;
            }

            return fallback;
        }

        private static double ReadDouble(JObject obj, string name, double fallback)
        {
            if (obj == null || obj[name] == null)
            {
                return fallback;
            }

            double value;

            if (double.TryParse(
                obj[name].ToString(),
                NumberStyles.Any,
                CultureInfo.InvariantCulture,
                out value))
            {
                return value;
            }

            return fallback;
        }

        private static string FormatBaseModelScores(JToken token)
        {
            if (token == null || token.Type == JTokenType.Null)
            {
                return "";
            }

            try
            {
                JObject obj = token as JObject;

                if (obj == null)
                {
                    return token.ToString(Formatting.None);
                }

                var parts = new List<string>();

                foreach (var prop in obj.Properties())
                {
                    double value = 0;

                    if (double.TryParse(
                        prop.Value.ToString(),
                        NumberStyles.Any,
                        CultureInfo.InvariantCulture,
                        out value))
                    {
                        parts.Add(prop.Name + "=" + value.ToString("0.0000", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        parts.Add(prop.Name + "=" + prop.Value);
                    }
                }

                return string.Join(", ", parts);
            }
            catch
            {
                return token.ToString(Formatting.None);
            }
        }

        private string BuildDefaultPayloadText()
        {
            var samples = BuildSamples();
            return string.Join(Environment.NewLine, samples.Select(x => x.JsonPayload));
        }

        private List<ApiGatewayComparisonInput> BuildSamples()
        {
            return new List<ApiGatewayComparisonInput>
            {
                new ApiGatewayComparisonInput
                {
                    Name = "Normal - duyệt menu nhẹ",
                    ExpectedLabel = "normal",
                    JsonPayload = "{\"case_name\":\"Normal - duyệt menu nhẹ\",\"expected_label\":\"normal\",\"inter_api_access_duration\":8,\"api_access_uniqueness\":0.8,\"sequence_length\":8,\"vsession_duration\":30,\"num_sessions\":3,\"num_users\":3,\"num_unique_apis\":8,\"request_rate_per_min\":0.26,\"graph_num_nodes\":15,\"graph_num_edges\":20,\"graph_density\":0.095,\"graph_self_loops\":1,\"graph_avg_degree\":2.66,\"controller\":\"Admin\",\"action_name\":\"Menus\"}"
                },
                new ApiGatewayComparisonInput
                {
                    Name = "Normal - admin xem dashboard",
                    ExpectedLabel = "normal",
                    JsonPayload = "{\"case_name\":\"Normal - admin xem dashboard\",\"expected_label\":\"normal\",\"inter_api_access_duration\":6,\"api_access_uniqueness\":0.9,\"sequence_length\":20,\"vsession_duration\":60,\"num_sessions\":5,\"num_users\":5,\"num_unique_apis\":25,\"request_rate_per_min\":0.33,\"graph_num_nodes\":30,\"graph_num_edges\":45,\"graph_density\":0.052,\"graph_self_loops\":2,\"graph_avg_degree\":3.0,\"controller\":\"Admin\",\"action_name\":\"Dashboard\"}"
                },
                new ApiGatewayComparisonInput
                {
                    Name = "Abnormal - request rate cao",
                    ExpectedLabel = "abnormal",
                    JsonPayload = "{\"case_name\":\"Abnormal - request rate cao\",\"expected_label\":\"abnormal\",\"inter_api_access_duration\":0.05,\"api_access_uniqueness\":0.1,\"sequence_length\":90,\"vsession_duration\":1,\"num_sessions\":1,\"num_users\":1,\"num_unique_apis\":3,\"request_rate_per_min\":90,\"graph_num_nodes\":3,\"graph_num_edges\":120,\"graph_density\":0.5,\"graph_self_loops\":30,\"graph_avg_degree\":80,\"controller\":\"Admin\",\"action_name\":\"ApiGatewayLogs\"}"
                },
                new ApiGatewayComparisonInput
                {
                    Name = "Abnormal - bot crawl nhiều API",
                    ExpectedLabel = "abnormal",
                    JsonPayload = "{\"case_name\":\"Abnormal - bot crawl nhiều API\",\"expected_label\":\"abnormal\",\"inter_api_access_duration\":0.8,\"api_access_uniqueness\":0.6,\"sequence_length\":180,\"vsession_duration\":20,\"num_sessions\":1,\"num_users\":1,\"num_unique_apis\":80,\"request_rate_per_min\":9.0,\"graph_num_nodes\":80,\"graph_num_edges\":160,\"graph_density\":0.025,\"graph_self_loops\":6,\"graph_avg_degree\":4.0,\"controller\":\"Admin\",\"action_name\":\"Foods\"}"
                },
                new ApiGatewayComparisonInput
                {
                    Name = "Abnormal - self-loop cao",
                    ExpectedLabel = "abnormal",
                    JsonPayload = "{\"case_name\":\"Abnormal - self-loop cao\",\"expected_label\":\"abnormal\",\"inter_api_access_duration\":0.1,\"api_access_uniqueness\":0.05,\"sequence_length\":200,\"vsession_duration\":3,\"num_sessions\":1,\"num_users\":1,\"num_unique_apis\":4,\"request_rate_per_min\":66,\"graph_num_nodes\":8,\"graph_num_edges\":400,\"graph_density\":7.1,\"graph_self_loops\":138,\"graph_avg_degree\":100,\"controller\":\"Account\",\"action_name\":\"Login\"}"
                }
            };
        }
    }

    public class ApiGatewayComparisonViewModel
    {
        public string JsonPayloads { get; set; }
        public bool HasResult { get; set; }
        public List<ApiGatewayComparisonInput> Samples { get; set; }
        public List<ApiGatewayComparisonRow> Rows { get; set; }
        public ApiGatewayComparisonSummary Summary { get; set; }
    }

    public class ApiGatewayComparisonInput
    {
        public string Name { get; set; }
        public string ExpectedLabel { get; set; }
        public string JsonPayload { get; set; }
    }

    public class ApiGatewayComparisonRow
    {
        public string Name { get; set; }
        public string ExpectedLabel { get; set; }
        public string JsonPayload { get; set; }
        public ApiGatewayComparisonResult OldResult { get; set; }
        public ApiGatewayComparisonResult NewResult { get; set; }
        public bool OldCorrect { get; set; }
        public bool NewCorrect { get; set; }
        public bool LabelChanged { get; set; }
        public double ScoreDifference { get; set; }
    }

    public class ApiGatewayComparisonResult
    {
        public string DisplayName { get; set; }
        public bool IsOnline { get; set; }
        public string ErrorMessage { get; set; }
        public string RawJson { get; set; }
        public string ModelName { get; set; }
        public string PredictedLabel { get; set; }
        public bool IsAbnormal { get; set; }
        public double RiskScore { get; set; }
        public double MlRiskScore { get; set; }
        public double AttackScore { get; set; }
        public double NormalScore { get; set; }
        public double Threshold { get; set; }
        public double ResponseTimeMs { get; set; }
        public string DecisionSource { get; set; }
        public string MetaModel { get; set; }
        public string BaseModelScores { get; set; }
        public string Action { get; set; }
    }

    public class ApiGatewayComparisonSummary
    {
        public int Total { get; set; }
        public int OldOnline { get; set; }
        public int NewOnline { get; set; }
        public int OldCorrect { get; set; }
        public int NewCorrect { get; set; }
        public int LabelChanged { get; set; }
        public double OldAvgRisk { get; set; }
        public double NewAvgRisk { get; set; }
        public double OldAvgTimeMs { get; set; }
        public double NewAvgTimeMs { get; set; }
    }
}

