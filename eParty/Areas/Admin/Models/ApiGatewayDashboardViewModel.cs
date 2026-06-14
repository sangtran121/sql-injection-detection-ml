using eParty.Models;
using System.Collections.Generic;

namespace eParty.Areas.Admin.Models
{
    public class ApiGatewayDashboardViewModel
    {
        public int TotalLogs { get; set; }
        public int TodayLogs { get; set; }
        public int Last24hLogs { get; set; }

        public int AllowCount { get; set; }
        public int MonitorCount { get; set; }
        public int ChallengeCount { get; set; }
        public int BlockCount { get; set; }
        public int ActiveBlockedIpCount { get; set; }
        public int TotalBlockedIpCount { get; set; }

        public int NormalCount { get; set; }
        public int AbnormalCount { get; set; }

        public double AverageRiskScore { get; set; }
        public double MaxRiskScore { get; set; }

        public List<string> HourLabels { get; set; }
        public List<int> HourAllowCounts { get; set; }
        public List<int> HourMonitorCounts { get; set; }
        public List<int> HourChallengeCounts { get; set; }
        public List<int> HourBlockCounts { get; set; }

        public List<string> ActionLabels { get; set; }
        public List<int> ActionCounts { get; set; }

        public List<string> TopIpLabels { get; set; }
        public List<int> TopIpCounts { get; set; }

        public List<string> TopRouteLabels { get; set; }
        public List<int> TopRouteCounts { get; set; }

        public List<ApiGatewayLog> RecentLogs { get; set; }
        public bool MlServiceOnline { get; set; }
        public string MlServiceStatus { get; set; }
        public string MlModelType { get; set; }
        public int MlFeatureCount { get; set; }
        public string MlErrorMessage { get; set; }

        public ApiGatewayDashboardViewModel()
        {
            HourLabels = new List<string>();
            HourAllowCounts = new List<int>();
            HourMonitorCounts = new List<int>();
            HourChallengeCounts = new List<int>();
            HourBlockCounts = new List<int>();

            ActionLabels = new List<string>();
            ActionCounts = new List<int>();

            TopIpLabels = new List<string>();
            TopIpCounts = new List<int>();

            TopRouteLabels = new List<string>();
            TopRouteCounts = new List<int>();

            RecentLogs = new List<ApiGatewayLog>();
        }
    }
}