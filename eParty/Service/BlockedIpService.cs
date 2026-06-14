using eParty.Models;
using System;
using System.Linq;

namespace eParty.Service
{
    public static class BlockedIpService
    {
        private const int WINDOW_MINUTES = 1;
        private const int BLOCK_MINUTES = 5;
        private const int MAX_CHALLENGE_COUNT = 10;

        public static ApiGatewayMlResult GetBlockedResultIfActive(string ipAddress)
        {
            ipAddress = NormalizeIp(ipAddress);

            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                return null;
            }

            try
            {
                DateTime now = DateTime.Now;

                using (var db = new AppDbContext())
                {
                    var activeBlock = db.BlockedIps
                        .Where(x =>
                            x.IpAddress == ipAddress &&
                            x.IsActive &&
                            x.BlockedUntil > now
                        )
                        .OrderByDescending(x => x.Id)
                        .FirstOrDefault();

                    if (activeBlock != null)
                    {
                        activeBlock.BlockedRequestCount += 1;
                        activeBlock.LastUpdatedAt = now;
                        db.SaveChanges();

                        return ApiGatewayMlResult.Block(
                            1.0,
                            "temporary_ip_block"
                        );
                    }

                    // Nếu có block đã hết hạn thì tự deactivate
                    var expiredBlocks = db.BlockedIps
                        .Where(x =>
                            x.IpAddress == ipAddress &&
                            x.IsActive &&
                            x.BlockedUntil <= now
                        )
                        .ToList();

                    foreach (var item in expiredBlocks)
                    {
                        item.IsActive = false;
                        item.UnblockedAt = now;
                        item.LastUpdatedAt = now;
                    }

                    if (expiredBlocks.Any())
                    {
                        db.SaveChanges();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[Blocked IP] Check active block error: " + ex.Message
                );
            }

            return null;
        }

        public static ApiGatewayMlResult ApplyTemporaryBlockPolicy(
    ApiGatewayFeaturePayload payload,
    ApiGatewayMlResult result
)
        {
            if (payload == null || result == null)
            {
                return result;
            }

            string ipAddress = NormalizeIp(payload.IpAddress);

            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                return result;
            }

            try
            {
                string action = (result.Action ?? "allow").ToLowerInvariant();

                bool isBadAction =
                    action == "challenge_or_rate_limit" ||
                    action == "block";

                if (!isBadAction)
                {
                    return result;
                }

                DateTime now = DateTime.Now;
                DateTime fromTime = now.AddMinutes(-WINDOW_MINUTES);

                using (var db = new AppDbContext())
                {
                    int recentChallengeCount = db.ApiGatewayLogs.Count(x =>
                        x.IpAddress == ipAddress &&
                        x.CreatedAt >= fromTime &&
                        (
                            x.FinalAction == "challenge_or_rate_limit" ||
                            x.FinalAction == "block"
                        )
                    );

                    // Cộng thêm request hiện tại vì log hiện tại chưa ghi DB
                    recentChallengeCount += 1;

                    bool shouldBlock =
                        recentChallengeCount >= MAX_CHALLENGE_COUNT ||
                        action == "block";

                    if (!shouldBlock)
                    {
                        return result;
                    }

                    bool createdNewBlock;

                    BlockedIp blockedIp = CreateOrExtendBlock(
                        db,
                        ipAddress,
                        recentChallengeCount,
                        result.DecisionSource,
                        out createdNewBlock
                    );

                    // Chỉ gửi Telegram khi tạo block mới.
                    // Không gửi mỗi request 403 để tránh spam Telegram.
                    if (createdNewBlock && blockedIp != null)
                    {
                        ApiGatewayTelegramAlertService.NotifyTemporaryBlockCreated(
                            blockedIp,
                            payload,
                            result
                        );
                    }

                    return ApiGatewayMlResult.Block(
                        1.0,
                        "temporary_ip_block_created"
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[Blocked IP] Apply policy error: " + ex.Message
                );

                return result;
            }
        }

        private static BlockedIp CreateOrExtendBlock(
    AppDbContext db,
    string ipAddress,
    int challengeCount,
    string source,
    out bool createdNewBlock
)
        {
            createdNewBlock = false;

            DateTime now = DateTime.Now;
            DateTime blockedUntil = now.AddMinutes(BLOCK_MINUTES);

            var activeBlock = db.BlockedIps
                .Where(x =>
                    x.IpAddress == ipAddress &&
                    x.IsActive &&
                    x.BlockedUntil > now
                )
                .OrderByDescending(x => x.Id)
                .FirstOrDefault();

            if (activeBlock != null)
            {
                activeBlock.BlockedUntil = blockedUntil;
                activeBlock.ChallengeCount = challengeCount;
                activeBlock.Source = SafeLength(source, 100);
                activeBlock.Reason = SafeLength(
                    "IP exceeded API Gateway temporary block threshold.",
                    500
                );
                activeBlock.LastUpdatedAt = now;

                db.SaveChanges();

                return activeBlock;
            }

            var blockedIp = new BlockedIp
            {
                IpAddress = SafeLength(ipAddress, 50),
                Source = SafeLength(source, 100),
                Reason = SafeLength(
                    "IP exceeded API Gateway temporary block threshold.",
                    500
                ),
                ChallengeCount = challengeCount,
                BlockedRequestCount = 0,
                BlockedUntil = blockedUntil,
                CreatedAt = now,
                LastUpdatedAt = now,
                IsActive = true
            };

            db.BlockedIps.Add(blockedIp);
            db.SaveChanges();

            createdNewBlock = true;

            return blockedIp;
        }

        private static string NormalizeIp(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
            {
                return "";
            }

            return ipAddress.Trim();
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