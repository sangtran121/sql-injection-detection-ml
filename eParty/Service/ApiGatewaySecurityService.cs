using eParty.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace eParty.Service
{
    /// <summary>
    /// Service trung tâm để xây dựng feature realtime cho API Gateway ML.
    ///
    /// Nhiệm vụ:
    /// - Theo dõi request trong Session
    /// - Tính request rate
    /// - Tính API uniqueness
    /// - Tính graph feature đơn giản từ chuỗi Controller/Action
    /// - Gửi payload 13 feature sang Flask detector
    ///
    /// Flask endpoint:
    /// POST http://localhost:5001/predict-api-gateway
    /// </summary>
    public class ApiGatewaySecurityService
    {
        private readonly ApiGatewayMlService _mlService;

        // Session keys
        private const string SESSION_START_KEY = "ApiGateway_SessionStartUtc";
        private const string LAST_REQUEST_KEY = "ApiGateway_LastRequestUtc";
        private const string REQUEST_COUNT_KEY = "ApiGateway_RequestCount";
        private const string API_HISTORY_KEY = "ApiGateway_ApiHistory";
        private const string REQUEST_TIMESTAMPS_KEY = "ApiGateway_RequestTimestamps";

        // Giới hạn history để session không phình quá lớn
        private const int MAX_API_HISTORY = 200;
        private const int MAX_TIMESTAMP_HISTORY = 300;

        // Sliding window để tính request_rate_per_min
        private const int RATE_WINDOW_SECONDS = 60;

        // Theo dõi thống kê đơn giản theo IP trong RAM
        private static readonly object _statsLock = new object();

        private static readonly Dictionary<string, Dictionary<string, DateTime>> _ipSessions =
            new Dictionary<string, Dictionary<string, DateTime>>();

        private static readonly Dictionary<string, Dictionary<string, DateTime>> _ipUsers =
            new Dictionary<string, Dictionary<string, DateTime>>();
        private static readonly Dictionary<string, List<DateTime>> _ipRequestTimestamps =
            new Dictionary<string, List<DateTime>>();

        private static readonly Dictionary<string, List<IpApiHit>> _ipApiHistories =
            new Dictionary<string, List<IpApiHit>>();

        private const int IP_REQUEST_WINDOW_SECONDS = 60;
        private const int MAX_IP_API_HISTORY = 300;

        private const int IP_STATS_TTL_MINUTES = 10;

        public ApiGatewaySecurityService()
        {
            _mlService = new ApiGatewayMlService();
        }

        public ApiGatewaySecurityService(ApiGatewayMlService mlService)
        {
            _mlService = mlService ?? new ApiGatewayMlService();
        }

        /// <summary>
        /// Hàm chính được Filter gọi.
        /// Tính payload rồi gửi sang Flask.
        /// </summary>
        public async Task<ApiGatewayMlResult> EvaluateAsync(HttpContextBase context)
        {
            if (context == null)
            {
                return ApiGatewayMlResult.Allow("fallback_null_context");
            }

            try
            {
                ApiGatewayFeaturePayload payload = BuildPayload(context);

                ApiGatewayMlResult result = await _mlService
                    .PredictAsync(payload)
                    .ConfigureAwait(false);

                // Ghi log xuống database.
                // Nếu log lỗi thì ApiGatewayLogService tự catch, không làm crash request.
                ApiGatewayLogService.WriteLog(context, payload, result);

                return result;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway Security] EvaluateAsync error: " + ex.Message
                );

                ApiGatewayMlResult fallbackResult =
                    ApiGatewayMlResult.Allow("fallback_security_exception");

                try
                {
                    ApiGatewayFeaturePayload fallbackPayload = BuildPayload(context);
                    ApiGatewayLogService.WriteLog(context, fallbackPayload, fallbackResult);
                }
                catch
                {
                    // ignored
                }

                return fallbackResult;
            }
        }

        /// <summary>
        /// Xây dựng payload đúng 13 feature cho Flask detector v6.
        /// </summary>
        public ApiGatewayFeaturePayload BuildPayload(HttpContextBase context)
        {
            DateTime now = DateTime.UtcNow;

            string controller = GetRouteValue(context, "controller", "Unknown");
            string action = GetRouteValue(context, "action", "Unknown");

            string currentApi = controller + "/" + action;

            string ip = GetClientIp(context);
            string sessionId = GetSessionId(context);
            string userName = GetUserName(context);

            DateTime sessionStart = GetOrSetSessionStart(context, now);
            double vsessionDurationMinutes = Math.Max((now - sessionStart).TotalMinutes, 0.001);

            double interRequestSeconds = GetAndUpdateInterRequestSeconds(context, now);

            int sessionSequenceLength = GetAndUpdateRequestCount(context);

            List<string> sessionApiHistory = GetAndUpdateApiHistory(context, currentApi);
            List<DateTime> sessionTimestamps = GetAndUpdateRequestTimestamps(context, now);

            // Theo dõi thêm theo IP để chống bypass bằng request không có cookie/session
            IpWindowStats ipWindowStats = UpdateAndGetIpWindowStats(ip, currentApi, now);

            // sequence_length hiệu dụng lấy max giữa session và IP window
            int sequenceLength = Math.Max(sessionSequenceLength, ipWindowStats.RequestCount);

            // Chọn history nào dài hơn để tính graph
            List<string> apiHistory = sessionApiHistory.Count >= ipWindowStats.ApiHistory.Count
                ? sessionApiHistory
                : ipWindowStats.ApiHistory;

            int numUniqueApis = apiHistory.Distinct(StringComparer.OrdinalIgnoreCase).Count();

            double apiAccessUniqueness = sequenceLength <= 0
                ? 0
                : (double)numUniqueApis / sequenceLength;

            apiAccessUniqueness = Clamp(apiAccessUniqueness, 0, 1);

            int graphNumNodes = numUniqueApis;
            int graphNumEdges = Math.Max(apiHistory.Count - 1, 0);
            int graphSelfLoops = CountSelfLoops(apiHistory);

            double graphDensity = 0;

            if (graphNumNodes > 1)
            {
                graphDensity = (double)graphNumEdges / (graphNumNodes * (graphNumNodes - 1));
            }

            double graphAvgDegree = graphNumNodes == 0
                ? 0
                : (2.0 * graphNumEdges) / graphNumNodes;

            
            int sessionRecentRequestCount = sessionTimestamps.Count(
    t => (now - t).TotalSeconds <= RATE_WINDOW_SECONDS
);

            // Dùng max giữa session rate và IP rate
            int recentRequestCount = Math.Max(
                sessionRecentRequestCount,
                ipWindowStats.RequestCount
            );

            double requestRatePerMin = recentRequestCount;

            var ipStats = UpdateAndGetIpStats(ip, sessionId, userName, now);

            return new ApiGatewayFeaturePayload
            {
                InterApiAccessDuration = interRequestSeconds,
                ApiAccessUniqueness = apiAccessUniqueness,
                SequenceLength = sequenceLength,
                VsessionDuration = vsessionDurationMinutes,

                NumSessions = ipStats.ActiveSessions,
                NumUsers = ipStats.ActiveUsers,

                NumUniqueApis = numUniqueApis,
                RequestRatePerMin = requestRatePerMin,

                GraphNumNodes = graphNumNodes,
                GraphNumEdges = graphNumEdges,
                GraphDensity = graphDensity,
                GraphSelfLoops = graphSelfLoops,
                GraphAvgDegree = graphAvgDegree,

                Controller = controller,
                ActionName = action,
                IpAddress = ip,
                SessionId = sessionId,
                Username = userName
            };
        }

        // ============================================================
        // SESSION FEATURE HELPERS
        // ============================================================

        private DateTime GetOrSetSessionStart(HttpContextBase context, DateTime now)
        {
            if (context.Session == null)
            {
                return now;
            }

            object value = context.Session[SESSION_START_KEY];

            if (value is DateTime)
            {
                return (DateTime)value;
            }

            context.Session[SESSION_START_KEY] = now;
            return now;
        }

        private double GetAndUpdateInterRequestSeconds(HttpContextBase context, DateTime now)
        {
            if (context.Session == null)
            {
                return 1.0;
            }

            double interSeconds = 1.0;

            object value = context.Session[LAST_REQUEST_KEY];

            if (value is DateTime)
            {
                DateTime last = (DateTime)value;
                interSeconds = Math.Max((now - last).TotalSeconds, 0.001);
            }

            context.Session[LAST_REQUEST_KEY] = now;

            return interSeconds;
        }

        private int GetAndUpdateRequestCount(HttpContextBase context)
        {
            if (context.Session == null)
            {
                return 1;
            }

            int count = 0;

            object value = context.Session[REQUEST_COUNT_KEY];

            if (value is int)
            {
                count = (int)value;
            }

            count++;

            context.Session[REQUEST_COUNT_KEY] = count;

            return count;
        }

        private List<string> GetAndUpdateApiHistory(HttpContextBase context, string currentApi)
        {
            List<string> history = null;

            if (context.Session != null)
            {
                history = context.Session[API_HISTORY_KEY] as List<string>;
            }

            if (history == null)
            {
                history = new List<string>();
            }

            history.Add(currentApi);

            if (history.Count > MAX_API_HISTORY)
            {
                history = history.Skip(history.Count - MAX_API_HISTORY).ToList();
            }

            if (context.Session != null)
            {
                context.Session[API_HISTORY_KEY] = history;
            }

            return history;
        }

        private List<DateTime> GetAndUpdateRequestTimestamps(HttpContextBase context, DateTime now)
        {
            List<DateTime> timestamps = null;

            if (context.Session != null)
            {
                timestamps = context.Session[REQUEST_TIMESTAMPS_KEY] as List<DateTime>;
            }

            if (timestamps == null)
            {
                timestamps = new List<DateTime>();
            }

            timestamps.Add(now);

            // Xóa timestamp quá cũ
            timestamps = timestamps
                .Where(t => (now - t).TotalSeconds <= RATE_WINDOW_SECONDS)
                .ToList();

            if (timestamps.Count > MAX_TIMESTAMP_HISTORY)
            {
                timestamps = timestamps.Skip(timestamps.Count - MAX_TIMESTAMP_HISTORY).ToList();
            }

            if (context.Session != null)
            {
                context.Session[REQUEST_TIMESTAMPS_KEY] = timestamps;
            }

            return timestamps;
        }

        private int CountSelfLoops(List<string> apiHistory)
        {
            if (apiHistory == null || apiHistory.Count < 2)
            {
                return 0;
            }

            int loops = 0;

            for (int i = 1; i < apiHistory.Count; i++)
            {
                if (string.Equals(apiHistory[i], apiHistory[i - 1], StringComparison.OrdinalIgnoreCase))
                {
                    loops++;
                }
            }

            return loops;
        }

        // ============================================================
        // IP / USER STATS
        // ============================================================

        private IpStats UpdateAndGetIpStats(string ip, string sessionId, string userName, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                ip = "unknown";
            }

            if (string.IsNullOrWhiteSpace(sessionId))
            {
                sessionId = "no-session";
            }

            if (string.IsNullOrWhiteSpace(userName))
            {
                userName = "anonymous";
            }

            lock (_statsLock)
            {
                CleanupIpStats(now);

                if (!_ipSessions.ContainsKey(ip))
                {
                    _ipSessions[ip] = new Dictionary<string, DateTime>();
                }

                if (!_ipUsers.ContainsKey(ip))
                {
                    _ipUsers[ip] = new Dictionary<string, DateTime>();
                }

                _ipSessions[ip][sessionId] = now;
                _ipUsers[ip][userName] = now;

                int activeSessions = _ipSessions[ip].Count;
                int activeUsers = _ipUsers[ip].Count;

                if (activeSessions <= 0)
                {
                    activeSessions = 1;
                }

                if (activeUsers <= 0)
                {
                    activeUsers = 1;
                }

                return new IpStats
                {
                    ActiveSessions = activeSessions,
                    ActiveUsers = activeUsers
                };
            }
        }
        private IpWindowStats UpdateAndGetIpWindowStats(string ip, string currentApi, DateTime now)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                ip = "unknown";
            }

            if (string.IsNullOrWhiteSpace(currentApi))
            {
                currentApi = "Unknown/Unknown";
            }

            lock (_statsLock)
            {
                if (!_ipRequestTimestamps.ContainsKey(ip))
                {
                    _ipRequestTimestamps[ip] = new List<DateTime>();
                }

                if (!_ipApiHistories.ContainsKey(ip))
                {
                    _ipApiHistories[ip] = new List<IpApiHit>();
                }

                _ipRequestTimestamps[ip].Add(now);

                _ipApiHistories[ip].Add(new IpApiHit
                {
                    Api = currentApi,
                    Time = now
                });

                // Chỉ giữ request trong 60 giây gần nhất
                _ipRequestTimestamps[ip] = _ipRequestTimestamps[ip]
                    .Where(t => (now - t).TotalSeconds <= IP_REQUEST_WINDOW_SECONDS)
                    .ToList();

                _ipApiHistories[ip] = _ipApiHistories[ip]
                    .Where(h => (now - h.Time).TotalSeconds <= IP_REQUEST_WINDOW_SECONDS)
                    .ToList();

                if (_ipApiHistories[ip].Count > MAX_IP_API_HISTORY)
                {
                    _ipApiHistories[ip] = _ipApiHistories[ip]
                        .Skip(_ipApiHistories[ip].Count - MAX_IP_API_HISTORY)
                        .ToList();
                }

                return new IpWindowStats
                {
                    RequestCount = _ipRequestTimestamps[ip].Count,
                    ApiHistory = _ipApiHistories[ip]
                        .Select(h => h.Api)
                        .ToList()
                };
            }
        }

        private void CleanupIpStats(DateTime now)
        {
            CleanupDictionary(_ipSessions, now);
            CleanupDictionary(_ipUsers, now);
        }

        private void CleanupDictionary(Dictionary<string, Dictionary<string, DateTime>> store, DateTime now)
        {
            var ipKeys = store.Keys.ToList();

            foreach (string ip in ipKeys)
            {
                var inner = store[ip];

                var expiredKeys = inner
                    .Where(kvp => (now - kvp.Value).TotalMinutes > IP_STATS_TTL_MINUTES)
                    .Select(kvp => kvp.Key)
                    .ToList();

                foreach (string key in expiredKeys)
                {
                    inner.Remove(key);
                }

                if (inner.Count == 0)
                {
                    store.Remove(ip);
                }
            }
        }

        // ============================================================
        // REQUEST HELPERS
        // ============================================================

        private string GetRouteValue(HttpContextBase context, string key, string defaultValue)
        {
            try
            {
                object value = context.Request.RequestContext.RouteData.Values[key];

                if (value == null)
                {
                    return defaultValue;
                }

                return Convert.ToString(value);
            }
            catch
            {
                return defaultValue;
            }
        }

        private string GetClientIp(HttpContextBase context)
        {
            try
            {
                string forwarded = context.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

                if (!string.IsNullOrWhiteSpace(forwarded))
                {
                    return forwarded.Split(',')[0].Trim();
                }

                string realIp = context.Request.ServerVariables["HTTP_X_REAL_IP"];

                if (!string.IsNullOrWhiteSpace(realIp))
                {
                    return realIp.Trim();
                }

                string userHostAddress = context.Request.UserHostAddress;

                if (!string.IsNullOrWhiteSpace(userHostAddress))
                {
                    return userHostAddress.Trim();
                }
            }
            catch
            {
                // ignored
            }

            return "unknown";
        }

        private string GetSessionId(HttpContextBase context)
        {
            try
            {
                if (context.Session != null && !string.IsNullOrWhiteSpace(context.Session.SessionID))
                {
                    return context.Session.SessionID;
                }
            }
            catch
            {
                // ignored
            }

            return "no-session";
        }

        private string GetUserName(HttpContextBase context)
        {
            try
            {
                if (
                    context.User != null &&
                    context.User.Identity != null &&
                    context.User.Identity.IsAuthenticated &&
                    !string.IsNullOrWhiteSpace(context.User.Identity.Name)
                )
                {
                    return context.User.Identity.Name;
                }
            }
            catch
            {
                // ignored
            }

            return "anonymous";
        }

        private double Clamp(double value, double min, double max)
        {
            if (value < min)
            {
                return min;
            }

            if (value > max)
            {
                return max;
            }

            return value;
        }
    }

    /// <summary>
    /// Payload gửi sang Flask.
    ///
    /// Tên property dùng snake_case nhờ Newtonsoft.Json JsonProperty.
    /// Phải khớp với api_gateway_detector.py.
    /// </summary>
    public class ApiGatewayFeaturePayload
    {
        [Newtonsoft.Json.JsonProperty("inter_api_access_duration")]
        public double InterApiAccessDuration { get; set; }

        [Newtonsoft.Json.JsonProperty("api_access_uniqueness")]
        public double ApiAccessUniqueness { get; set; }

        [Newtonsoft.Json.JsonProperty("sequence_length")]
        public double SequenceLength { get; set; }

        [Newtonsoft.Json.JsonProperty("vsession_duration")]
        public double VsessionDuration { get; set; }

        [Newtonsoft.Json.JsonProperty("num_sessions")]
        public double NumSessions { get; set; }

        [Newtonsoft.Json.JsonProperty("num_users")]
        public double NumUsers { get; set; }

        [Newtonsoft.Json.JsonProperty("num_unique_apis")]
        public double NumUniqueApis { get; set; }

        [Newtonsoft.Json.JsonProperty("request_rate_per_min")]
        public double RequestRatePerMin { get; set; }

        [Newtonsoft.Json.JsonProperty("graph_num_nodes")]
        public double GraphNumNodes { get; set; }

        [Newtonsoft.Json.JsonProperty("graph_num_edges")]
        public double GraphNumEdges { get; set; }

        [Newtonsoft.Json.JsonProperty("graph_density")]
        public double GraphDensity { get; set; }

        [Newtonsoft.Json.JsonProperty("graph_self_loops")]
        public double GraphSelfLoops { get; set; }

        [Newtonsoft.Json.JsonProperty("graph_avg_degree")]
        public double GraphAvgDegree { get; set; }

        [Newtonsoft.Json.JsonProperty("controller")]
        public string Controller { get; set; }

        [Newtonsoft.Json.JsonProperty("action_name")]
        public string ActionName { get; set; }

        [Newtonsoft.Json.JsonProperty("ip_address")]
        public string IpAddress { get; set; }

        [Newtonsoft.Json.JsonProperty("session_id")]
        public string SessionId { get; set; }

        [Newtonsoft.Json.JsonProperty("username")]
        public string Username { get; set; }
    }

    /// <summary>
    /// Thống kê đơn giản theo IP.
    /// Dùng để ước lượng num_sessions và num_users.
    /// </summary>
    internal class IpStats
    {
        public int ActiveSessions { get; set; }
        public int ActiveUsers { get; set; }
    }
    internal class IpApiHit
    {
        public string Api { get; set; }
        public DateTime Time { get; set; }
    }

    internal class IpWindowStats
    {
        public int RequestCount { get; set; }
        public List<string> ApiHistory { get; set; }

        public IpWindowStats()
        {
            ApiHistory = new List<string>();
        }
    }
}