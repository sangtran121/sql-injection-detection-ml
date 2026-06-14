using Newtonsoft.Json;

namespace eParty.Models
{
    /// <summary>
    /// Kết quả trả về từ Flask API Gateway ML Detector.
    /// 
    /// Flask endpoint:
    /// POST http://localhost:5001/predict-api-gateway
    /// 
    /// JSON trả về ví dụ:
    /// {
    ///   "is_abnormal": true,
    ///   "risk_score": 0.9184,
    ///   "attack_score": 0.9184,
    ///   "predicted_label": "abnormal",
    ///   "rule_attack": true,
    ///   "action": "challenge_or_rate_limit",
    ///   "decision_source": "rule_softened"
    /// }
    /// </summary>
    public class ApiGatewayMlResult
    {
        /// <summary>
        /// True nếu request bị ML hoặc rule engine đánh giá là bất thường.
        /// </summary>
        [JsonProperty("is_abnormal")]
        public bool IsAbnormal { get; set; }

        /// <summary>
        /// Điểm rủi ro tổng.
        /// Với model binary v6:
        /// risk_score = abnormal_score.
        /// </summary>
        [JsonProperty("risk_score")]
        public double RiskScore { get; set; }

        /// <summary>
        /// Giữ lại để tương thích với code cũ.
        /// Với model binary v6, attack_score cũng chính là abnormal_score.
        /// </summary>
        [JsonProperty("attack_score")]
        public double AttackScore { get; set; }

        /// <summary>
        /// Nhãn dự đoán từ model.
        /// Giá trị hiện tại:
        /// - normal
        /// - abnormal
        /// </summary>
        [JsonProperty("predicted_label")]
        public string PredictedLabel { get; set; }

        /// <summary>
        /// True nếu rule engine phát hiện dấu hiệu tấn công rõ ràng.
        /// Ví dụ:
        /// - request rate quá cao
        /// - self-loop quá nhiều
        /// - graph edges quá cao
        /// - brute force/flood
        /// </summary>
        [JsonProperty("rule_attack")]
        public bool RuleAttack { get; set; }

        /// <summary>
        /// Hành động Flask đề xuất cho ASP.NET MVC.
        /// Giá trị có thể:
        /// - allow
        /// - monitor
        /// - challenge_or_rate_limit
        /// - block
        /// </summary>
        [JsonProperty("action")]
        public string Action { get; set; }

        /// <summary>
        /// Nguồn ra quyết định.
        /// Ví dụ:
        /// - normal
        /// - ml_monitor
        /// - ml_challenge
        /// - ml_high_risk
        /// - rule_rate_limit
        /// - rule_high_risk
        /// - rule_softened
        /// - cold_start_allow
        /// - fallback_model_not_loaded
        /// </summary>
        [JsonProperty("decision_source")]
        public string DecisionSource { get; set; }

        /// <summary>
        /// Tạo kết quả allow mặc định.
        /// Dùng khi Flask lỗi, timeout, không load model,
        /// hoặc khi muốn hệ thống không làm treo website.
        /// </summary>
        public static ApiGatewayMlResult Allow(string source = "fallback_allow")
        {
            return new ApiGatewayMlResult
            {
                IsAbnormal = false,
                RiskScore = 0,
                AttackScore = 0,
                PredictedLabel = "normal",
                RuleAttack = false,
                Action = "allow",
                DecisionSource = source
            };
        }

        /// <summary>
        /// Tạo kết quả monitor.
        /// Dùng khi request hơi bất thường nhưng chưa đủ mạnh để challenge/block.
        /// </summary>
        public static ApiGatewayMlResult Monitor(double riskScore, string source = "ml_monitor")
        {
            return new ApiGatewayMlResult
            {
                IsAbnormal = true,
                RiskScore = riskScore,
                AttackScore = riskScore,
                PredictedLabel = "abnormal",
                RuleAttack = false,
                Action = "monitor",
                DecisionSource = source
            };
        }

        /// <summary>
        /// Tạo kết quả challenge hoặc rate limit.
        /// Dùng khi request rủi ro cao nhưng chưa nên block cứng.
        /// </summary>
        public static ApiGatewayMlResult Challenge(double riskScore, string source = "ml_challenge")
        {
            return new ApiGatewayMlResult
            {
                IsAbnormal = true,
                RiskScore = riskScore,
                AttackScore = riskScore,
                PredictedLabel = "abnormal",
                RuleAttack = false,
                Action = "challenge_or_rate_limit",
                DecisionSource = source
            };
        }

        /// <summary>
        /// Tạo kết quả block.
        /// Chỉ nên dùng khi rule engine rất chắc chắn.
        /// Không nên block chỉ dựa vào ML score.
        /// </summary>
        public static ApiGatewayMlResult Block(double riskScore, string source = "rule_high_risk")
        {
            return new ApiGatewayMlResult
            {
                IsAbnormal = true,
                RiskScore = riskScore,
                AttackScore = riskScore,
                PredictedLabel = "abnormal",
                RuleAttack = true,
                Action = "block",
                DecisionSource = source
            };
        }

        /// <summary>
        /// Kiểm tra action có phải allow không.
        /// </summary>
        public bool IsAllow()
        {
            return string.Equals(Action, "allow", System.StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Kiểm tra action có phải monitor không.
        /// </summary>
        public bool IsMonitor()
        {
            return string.Equals(Action, "monitor", System.StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Kiểm tra action có phải challenge_or_rate_limit không.
        /// </summary>
        public bool IsChallengeOrRateLimit()
        {
            return string.Equals(Action, "challenge_or_rate_limit", System.StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Kiểm tra action có phải block không.
        /// </summary>
        public bool IsBlock()
        {
            return string.Equals(Action, "block", System.StringComparison.OrdinalIgnoreCase);
        }
    }
}