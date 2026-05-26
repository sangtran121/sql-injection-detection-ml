using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace eParty.Models
{
    public class PendingWhitelist
    {
        public int Id { get; set; }
        public string Payload { get; set; }
        public string Token { get; set; }  // token ngẫu nhiên để bảo mật
        public DateTime CreatedAt { get; set; }
        public bool IsUsed { get; set; }
    }
}