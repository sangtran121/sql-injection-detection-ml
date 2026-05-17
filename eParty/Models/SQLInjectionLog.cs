using System;
using System.ComponentModel.DataAnnotations;

namespace eParty.Models
{
    public class SQLInjectionLog
    {
        public int Id { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.Now;

        public string IpAddress { get; set; }

        public string Url { get; set; }

        public string SuspiciousInput { get; set; }

        public string Controller { get; set; }

        public string Action { get; set; }

        public string UserAgent { get; set; }

        public bool IsBlocked { get; set; } = true;

        // ================== CÁC CỘT MỚI ==================
        public double? Probability { get; set; }          // Xác suất từ ML Model
        public string DetectedBy { get; set; }            // "Rule-based" hoặc "ML Model"
        public string RequestMethod { get; set; }         // GET / POST
        public string UserId { get; set; }                // Nếu có user đăng nhập
    }
}