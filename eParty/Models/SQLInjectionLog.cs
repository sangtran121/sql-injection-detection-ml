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
    }
}