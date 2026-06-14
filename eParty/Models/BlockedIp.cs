using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace eParty.Models
{
    [Table("BlockedIps")]
    public class BlockedIp
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string IpAddress { get; set; }

        [StringLength(100)]
        public string Source { get; set; }

        [StringLength(500)]
        public string Reason { get; set; }

        public int ChallengeCount { get; set; }

        public int BlockedRequestCount { get; set; }

        public DateTime BlockedUntil { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime LastUpdatedAt { get; set; }

        public DateTime? UnblockedAt { get; set; }

        public bool IsActive { get; set; }
    }
}