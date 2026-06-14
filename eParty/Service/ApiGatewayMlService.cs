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
    /// Flask endpoint:
    /// POST http://localhost:5001/predict-api-gateway
    ///
    /// Nhiệm vụ:
    /// - Nhận payload 13 feature từ ApiGatewaySecurityService
    /// - Gửi sang Flask
    /// - Nhận kết quả normal/abnormal + action
    /// - Nếu Flask lỗi/timeout thì allow để không làm treo website
    /// </summary>
    public class ApiGatewayMlService
    {
        private static readonly HttpClient _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private readonly string _predictUrl;
        private readonly string _healthUrl;

        public ApiGatewayMlService()
        {
            _predictUrl = "http://127.0.0.1:5001/predict-api-gateway";
            _healthUrl = "http://127.0.0.1:5001/health";
        }

        public ApiGatewayMlService(string baseUrl)
        {
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                baseUrl = "http://127.0.0.1:5001";
            }

            baseUrl = baseUrl.TrimEnd('/');

            _predictUrl = baseUrl + "/predict-api-gateway";
            _healthUrl = baseUrl + "/health";
        }
        /// <summary>
        /// Gửi request feature sang Flask ML Detector.
        /// 
        /// Nếu Flask hoạt động:
        /// - Trả về ApiGatewayMlResult thật
        ///
        /// Nếu Flask lỗi:
        /// - Trả về allow fallback
        /// - Không throw exception ra MVC
        /// </summary>
        public async Task<ApiGatewayMlResult> PredictAsync(object payload)
        {
            if (payload == null)
            {
                return ApiGatewayMlResult.Allow("fallback_empty_payload");
            }

            try
            {
                string json = JsonConvert.SerializeObject(payload);

                using (var content = new StringContent(json, Encoding.UTF8, "application/json"))
                {
                    HttpResponseMessage response = await _httpClient
                        .PostAsync(_predictUrl, content)
                        .ConfigureAwait(false);

                    string responseBody = await response.Content
                        .ReadAsStringAsync()
                        .ConfigureAwait(false);

                    if (!response.IsSuccessStatusCode)
                    {
                        System.Diagnostics.Debug.WriteLine(
                            "[API Gateway ML] Flask returned HTTP "
                            + (int)response.StatusCode
                            + ": "
                            + responseBody
                        );

                        return ApiGatewayMlResult.Allow("fallback_http_error");
                    }

                    var result = JsonConvert.DeserializeObject<ApiGatewayMlResult>(responseBody);

                    if (result == null)
                    {
                        return ApiGatewayMlResult.Allow("fallback_empty_result");
                    }

                    NormalizeResult(result);

                    return result;
                }
            }
            catch (TaskCanceledException ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] Timeout khi gọi Flask: " + ex.Message
                );

                return ApiGatewayMlResult.Allow("fallback_timeout");
            }
            catch (HttpRequestException ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] Không kết nối được Flask: " + ex.Message
                );

                return ApiGatewayMlResult.Allow("fallback_connection_error");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway ML] Lỗi không xác định: " + ex.Message
                );

                return ApiGatewayMlResult.Allow("fallback_exception");
            }
        }

        /// <summary>
        /// Kiểm tra Flask /health có chạy không.
        /// Dùng để debug, không bắt buộc gọi trong filter.
        /// </summary>
        public async Task<bool> IsHealthyAsync()
        {
            try
            {
                HttpResponseMessage response = await _httpClient
                    .GetAsync(_healthUrl)
                    .ConfigureAwait(false);

                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Chuẩn hóa kết quả để tránh null hoặc action lạ.
        /// </summary>
        private void NormalizeResult(ApiGatewayMlResult result)
        {
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