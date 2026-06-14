using eParty.Models;
using System;
using System.Collections.Generic;

namespace eParty.Areas.Admin.Models
{
    public class ApiGatewayLogListViewModel
    {
        public List<ApiGatewayLog> Logs { get; set; }

        // Filter
        public string IpAddress { get; set; }
        public string FinalAction { get; set; }
        public string PredictedLabel { get; set; }
        public string DecisionSource { get; set; }
        public DateTime? FromDate { get; set; }
        public DateTime? ToDate { get; set; }

        // Paging
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int TotalItems { get; set; }
        public int TotalPages { get; set; }

        // Summary
        public int TotalLogs { get; set; }
        public int FilteredLogs { get; set; }
        public int AllowCount { get; set; }
        public int MonitorCount { get; set; }
        public int ChallengeCount { get; set; }
        public int BlockCount { get; set; }

        public ApiGatewayLogListViewModel()
        {
            Logs = new List<ApiGatewayLog>();
        }
    }
}