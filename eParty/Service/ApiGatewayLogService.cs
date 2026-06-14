using eParty.Models;
using System;
using System.Web;

namespace eParty.Service
{
    /// <summary>
    /// Ghi log kết quả API Gateway ML xuống database.
    ///
    /// Lưu ý:
    /// - Service này tuyệt đối không được làm crash website.
    /// - Nếu ghi log lỗi thì chỉ Debug.WriteLine rồi bỏ qua.
    /// - Không ảnh hưởng đến quyết định allow / monitor / 429 / 403.
    /// </summary>
    public static class ApiGatewayLogService
    {
        // true  = lưu cả allow/monitor/challenge/block
        // false = chỉ lưu monitor/challenge/block để database nhẹ hơn
        private const bool SAVE_ALLOW_LOGS = true;

        public static void WriteLog(
            HttpContextBase context,
            ApiGatewayFeaturePayload payload,
            ApiGatewayMlResult result
        )
        {
            try
            {
                if (context == null || payload == null || result == null)
                {
                    return;
                }

                string finalAction = (result.Action ?? "allow").ToLowerInvariant();

                if (!SAVE_ALLOW_LOGS && finalAction == "allow")
                {
                    return;
                }

                using (var db = new AppDbContext())
                {
                    var log = new ApiGatewayLog
                    {
                        // Request information
                        IpAddress = SafeLength(payload.IpAddress, 50),
                        SessionId = SafeLength(payload.SessionId, 128),
                        Username = SafeLength(payload.Username, 256),
                        Controller = SafeLength(payload.Controller, 100),
                        ActionName = SafeLength(payload.ActionName, 100),
                        RawUrl = SafeLength(GetRawUrl(context), 500),
                        HttpMethod = SafeLength(GetHttpMethod(context), 20),
                        UserAgent = SafeLength(GetUserAgent(context), 500),

                        // ML result
                        IsAbnormal = result.IsAbnormal,
                        RiskScore = result.RiskScore,
                        AttackScore = result.AttackScore,
                        PredictedLabel = SafeLength(result.PredictedLabel, 50),
                        RuleAttack = result.RuleAttack,
                        FinalAction = SafeLength(finalAction, 50),
                        DecisionSource = SafeLength(result.DecisionSource, 100),

                        // Features
                        InterApiAccessDuration = payload.InterApiAccessDuration,
                        ApiAccessUniqueness = payload.ApiAccessUniqueness,
                        SequenceLength = payload.SequenceLength,
                        VsessionDuration = payload.VsessionDuration,
                        NumSessions = payload.NumSessions,
                        NumUsers = payload.NumUsers,
                        NumUniqueApis = payload.NumUniqueApis,
                        RequestRatePerMin = payload.RequestRatePerMin,
                        GraphNumNodes = payload.GraphNumNodes,
                        GraphNumEdges = payload.GraphNumEdges,
                        GraphDensity = payload.GraphDensity,
                        GraphSelfLoops = payload.GraphSelfLoops,
                        GraphAvgDegree = payload.GraphAvgDegree,

                        CreatedAt = DateTime.Now
                    };

                    db.ApiGatewayLogs.Add(log);
                    db.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway Log] Không ghi được log DB: " + ex.Message
                );
            }
        }

        private static string GetRawUrl(HttpContextBase context)
        {
            try
            {
                return context.Request.RawUrl ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string GetHttpMethod(HttpContextBase context)
        {
            try
            {
                return context.Request.HttpMethod ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string GetUserAgent(HttpContextBase context)
        {
            try
            {
                return context.Request.UserAgent ?? "";
            }
            catch
            {
                return "";
            }
        }

        private static string SafeLength(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "";
            }

            value = value.Trim();

            if (value.Length <= maxLength)
            {
                return value;
            }

            return value.Substring(0, maxLength);
        }
    }
}