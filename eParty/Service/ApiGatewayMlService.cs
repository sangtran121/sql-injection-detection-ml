using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace eParty.Service
{
    /// <summary>
    /// Service gọi Flask API Gateway ML Detector.
    ///
    /// Luồng mới:
    /// - Ưu tiên API Gateway Stacking mới: 5011
    /// - Nếu 5011 lỗi / timeout / chưa chạy thì fallback về model cũ: 5001
    /// - Nếu cả 5011 và 5001 đều lỗi thì allow để website không bị treo
    ///
    /// Endpoint:
    /// - New : POST http://127.0.0.1:5011/predict-api-gateway
    /// - Old : POST http://127.0.0.1:5001/predict-api-gateway
    /// </summary>
    public class ApiGatewayMlService
    {
        private static readonly HttpClient _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private readonly string _newPredictUrl;
        private readonly string _newHealthUrl;

        private readonly string _oldPredictUrl;
        private readonly string _oldHealthUrl;

        public ApiGatewayMlService()
        {
            _newPredictUrl = "http://127.0.0.1:5011/predict-api-gateway";
            _newHealthUrl = "http://127.0.0.1:5011/health";

            _oldPredictUrl = "http://127.0.0.1:5001/predict-api-gateway";
            _oldHealthUrl = "http://127.0.0.1:5001/health";
        }

        /// <summary>
        /// Constructor tùy chỉnh primary baseUrl.
        /// Nếu truyền baseUrl thì baseUrl đó được xem là API chính.
        /// Fallback vẫn luôn là 5001.
        /// </summary>
        public ApiGatewayMlService(string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                baseUrl = "http://127.0.0.1:5011";
            }

            baseUrl = baseUrl.TrimEnd('/');

            _newPredictUrl = baseUrl + "/predict-api-gateway";
            _newHealthUrl = baseUrl + "/health";

            _oldPredictUrl = "http://127.0.0.1:5001/predict-api-gateway";
            _oldHealthUrl = "http://127.0.0.1:5001/health";
        }

        /// <summary>
        /// Gửi request feature sang Flask ML Detector.
        ///
        /// Thứ tự:
        /// 1. Gọi 5011 Stacking Ensemble
        /// 2. Nếu 5011 lỗi thì gọi 5001 baseline cũ
        /// 3. Nếu cả hai lỗi thì allow fallback
        /// </summary>
        public async Task<ApiGatewayMlResult> PredictAsync(object payload)
        {
            if (payload == null)
            {
                return ApiGatewayMlResult.Allow("fallback_empty_payload");
            }

            Exception newApiError = null;

            try
            {
                ApiGatewayMlResult newResult = await CallPredictApiAsync(
                    _newPredictUrl,
                    payload
                ).ConfigureAwait(false);

                NormalizeResult(newResult);
                TagResultSource(newResult, "new_5011");

                return newResult;
            }
            catch (Exception ex)
            {
                newApiError = ex;

                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] 5011 failed: " + ex.Message
                );
            }

            try
            {
                ApiGatewayMlResult oldResult = await CallPredictApiAsync(
                    _oldPredictUrl,
                    payload
                ).ConfigureAwait(false);

                NormalizeResult(oldResult);
                TagResultSource(oldResult, "fallback_5001");

                return oldResult;
            }
            catch (Exception oldEx)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] Both API failed. 5011: "
                    + (newApiError == null ? "unknown" : newApiError.Message)
                    + " | 5001: "
                    + oldEx.Message
                );

                return ApiGatewayMlResult.Allow("fallback_all_api_gateway_ml_down");
            }
        }

        /// <summary>
        /// Kiểm tra health:
        /// - Ưu tiên 5011
        /// - Nếu 5011 lỗi thì kiểm tra 5001
        /// - Nếu cả hai lỗi thì offline
        /// </summary>
        public async Task<ApiGatewayHealthResult> CheckHealthAsync()
        {
            Exception newApiError = null;

            try
            {
                ApiGatewayHealthResult newHealth = await CallHealthApiAsync(
                    _newHealthUrl
                ).ConfigureAwait(false);

                NormalizeHealthResult(newHealth, "new_5011");

                return newHealth;
            }
            catch (Exception ex)
            {
                newApiError = ex;

                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] Health 5011 failed: " + ex.Message
                );
            }

            try
            {
                ApiGatewayHealthResult oldHealth = await CallHealthApiAsync(
                    _oldHealthUrl
                ).ConfigureAwait(false);

                NormalizeHealthResult(oldHealth, "fallback_5001");

                oldHealth.ErrorMessage =
                    "Using fallback 5001 because 5011 failed: "
                    + (newApiError == null ? "unknown" : newApiError.Message);

                return oldHealth;
            }
            catch (Exception oldEx)
            {
                return ApiGatewayHealthResult.Offline(
                    "5011 failed: "
                    + (newApiError == null ? "unknown" : newApiError.Message)
                    + " | 5001 failed: "
                    + oldEx.Message
                );
            }
        }

        /// <summary>
        /// Kiểm tra Flask /health có chạy không.
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            ApiGatewayHealthResult health = await CheckHealthAsync()
                .ConfigureAwait(false);

            return health != null && health.IsOnline;
        }

        private async Task<ApiGatewayMlResult> CallPredictApiAsync(
            string url,
            object payload
        )
        {
            string json = JsonConvert.SerializeObject(payload);

            using (var content = new StringContent(json, Encoding.UTF8, "application/json"))
            {
                HttpResponseMessage response = await _httpClient
                    .PostAsync(url, content)
                    .ConfigureAwait(false);

                string responseBody = await response.Content
                    .ReadAsStringAsync()
                    .ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception(
                        "HTTP "
                        + (int)response.StatusCode
                        + " from "
                        + url
                        + ": "
                        + responseBody
                    );
                }

                ApiGatewayMlResult result =
                    JsonConvert.DeserializeObject<ApiGatewayMlResult>(responseBody);

                if (result == null)
                {
                    throw new Exception("Invalid or empty predict response from " + url);
                }

                return result;
            }
        }

        private async Task<ApiGatewayHealthResult> CallHealthApiAsync(string url)
        {
            using (HttpResponseMessage response = await _httpClient
                .GetAsync(url)
                .ConfigureAwait(false))
            {
                string json = await response.Content
                    .ReadAsStringAsync()
                    .ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw new Exception(
                        "HTTP "
                        + (int)response.StatusCode
                        + " from "
                        + url
                        + ": "
                        + json
                    );
                }

                ApiGatewayHealthResult result =
                    JsonConvert.DeserializeObject<ApiGatewayHealthResult>(json);

                if (result == null)
                {
                    throw new Exception("Invalid or empty health response from " + url);
                }

                return result;
            }
        }

        /// <summary>
        /// Gắn nguồn API vào DecisionSource để dashboard/log biết request đi qua 5011 hay fallback 5001.
        /// </summary>
        private void TagResultSource(ApiGatewayMlResult result, string apiSource)
        {
            if (result == null)
            {
                return;
            }

            string oldSource = string.IsNullOrWhiteSpace(result.DecisionSource)
                ? "ml"
                : result.DecisionSource.Trim();

            result.DecisionSource = apiSource + "_" + oldSource;

            if (result.DecisionSource.Length > 100)
            {
                result.DecisionSource = result.DecisionSource.Substring(0, 100);
            }
        }

        private void NormalizeHealthResult(ApiGatewayHealthResult result, string apiSource)
        {
            if (result == null)
            {
                return;
            }

            result.IsOnline = true;

            if (string.IsNullOrWhiteSpace(result.Status))
            {
                result.Status = "online";
            }

            if (string.IsNullOrWhiteSpace(result.ModelType))
            {
                result.ModelType = apiSource;
            }
            else
            {
                result.ModelType = result.ModelType + " (" + apiSource + ")";
            }

            if (string.IsNullOrWhiteSpace(result.ErrorMessage))
            {
                result.ErrorMessage = "";
            }
        }

        /// <summary>
        /// Chuẩn hóa kết quả để tránh null hoặc action lạ.
        /// </summary>
        private void NormalizeResult(ApiGatewayMlResult result)
        {
            if (result == null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(result.PredictedLabel))
            {
                result.PredictedLabel = result.IsAbnormal ? "abnormal" : "normal";
            }

            if (string.IsNullOrWhiteSpace(result.Action))
            {
                result.Action = result.IsAbnormal ? "monitor" : "allow";
            }

            if (string.IsNullOrWhiteSpace(result.DecisionSource))
            {
                result.DecisionSource = "ml";
            }

            result.Action = result.Action.ToLowerInvariant();
            result.PredictedLabel = result.PredictedLabel.ToLowerInvariant();

            if (
                result.Action != "allow" &&
                result.Action != "monitor" &&
                result.Action != "challenge_or_rate_limit" &&
                result.Action != "block"
            )
            {
                result.Action = result.IsAbnormal ? "monitor" : "allow";
                result.DecisionSource = "fallback_unknown_action";
            }

            if (result.RiskScore < 0)
            {
                result.RiskScore = 0;
            }

            if (result.RiskScore > 1)
            {
                result.RiskScore = 1;
            }

            if (result.AttackScore < 0)
            {
                result.AttackScore = 0;
            }

            if (result.AttackScore > 1)
            {
                result.AttackScore = 1;
            }
        }
    }
}

