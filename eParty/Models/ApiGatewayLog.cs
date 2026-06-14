using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace eParty.Models
{
    [Table("ApiGatewayLogs")]
    public class ApiGatewayLog
    {
        [Key]
        public int Id { get; set; }

        // =========================
        // Request information
        // =========================

        [StringLength(50)]
        public string IpAddress { get; set; }

        [StringLength(128)]
        public string SessionId { get; set; }

        [StringLength(256)]
        public string Username { get; set; }

        [StringLength(100)]
        public string Controller { get; set; }

        [StringLength(100)]
        public string ActionName { get; set; }

        [StringLength(500)]
        public string RawUrl { get; set; }

        [StringLength(20)]
        public string HttpMethod { get; set; }

        [StringLength(500)]
        public string UserAgent { get; set; }

        // =========================
        // ML result
        // =========================

        public bool IsAbnormal { get; set; }

        public double RiskScore { get; set; }

        public double AttackScore { get; set; }

        [StringLength(50)]
        public string PredictedLabel { get; set; }

        public bool RuleAttack { get; set; }

        [StringLength(50)]
        public string FinalAction { get; set; }

        [StringLength(100)]
        public string DecisionSource { get; set; }

        // =========================
        // API Gateway features
        // =========================

        public double InterApiAccessDuration { get; set; }

        public double ApiAccessUniqueness { get; set; }

        public double SequenceLength { get; set; }

        public double VsessionDuration { get; set; }

        public double NumSessions { get; set; }

        public double NumUsers { get; set; }

        public double NumUniqueApis { get; set; }

        public double RequestRatePerMin { get; set; }

        public double GraphNumNodes { get; set; }

        public double GraphNumEdges { get; set; }

        public double GraphDensity { get; set; }

        public double GraphSelfLoops { get; set; }

        public double GraphAvgDegree { get; set; }

        // =========================
        // Time
        // =========================

        public DateTime CreatedAt { get; set; }
    }
}