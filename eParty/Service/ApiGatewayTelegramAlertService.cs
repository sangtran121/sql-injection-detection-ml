using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Configuration;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace eParty.Service
{
    public static class ApiGatewayTelegramAlertService
    {
        private static readonly HttpClient _httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        private static readonly ConcurrentDictionary<string, DateTime> _lastAlertByKey =
            new ConcurrentDictionary<string, DateTime>();

        private const int ALERT_COOLDOWN_SECONDS = 60;

        public static void NotifyTemporaryBlockCreated(
            BlockedIp blockedIp,
            ApiGatewayFeaturePayload payload,
            ApiGatewayMlResult result
        )
        {
            try
            {
                if (!IsEnabled())
                {
                    return;
                }

                if (blockedIp == null || payload == null)
                {
                    return;
                }

                string ip = blockedIp.IpAddress ?? "unknown";
                string cooldownKey = "temporary_block:" + ip;

                if (IsInCooldown(cooldownKey))
                {
                    return;
                }

                string message = BuildTemporaryBlockMessage(
                    blockedIp,
                    payload,
                    result
                );

                Task.Run(async () =>
                {
                    await SendMessageAsync(message);
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway Telegram] Notify error: " + ex.Message
                );
            }
        }

        private static string BuildTemporaryBlockMessage(
            BlockedIp blockedIp,
            ApiGatewayFeaturePayload payload,
            ApiGatewayMlResult result
        )
        {
            string route = (payload.Controller ?? "Unknown") + "/" + (payload.ActionName ?? "Unknown");

            double riskScore = result != null ? result.RiskScore : 1.0;
            string source = result != null ? result.DecisionSource : blockedIp.Source;

            string message =
                "🚫 <b>API Gateway Temporary Block</b>\n\n" +

                "🌐 <b>IP:</b> <code>" + H(blockedIp.IpAddress) + "</code>\n" +
                "📍 <b>Route:</b> <code>" + H(route) + "</code>\n" +
                "🧠 <b>Source:</b> <code>" + H(source) + "</code>\n" +
                "⚠️ <b>Risk:</b> <code>" + riskScore.ToString("0.0000") + "</code>\n\n" +

                "📊 <b>Realtime Features</b>\n" +
                "• Request Rate: <code>" + payload.RequestRatePerMin.ToString("0.##") + "/min</code>\n" +
                "• Sequence Length: <code>" + payload.SequenceLength.ToString("0.##") + "</code>\n" +
                "• Graph Self Loops: <code>" + payload.GraphSelfLoops.ToString("0.##") + "</code>\n" +
                "• Challenge Count: <code>" + blockedIp.ChallengeCount + "</code>\n\n" +

                "⏰ <b>Blocked Until:</b> <code>" + blockedIp.BlockedUntil.ToString("dd/MM/yyyy HH:mm:ss") + "</code>\n" +
                "🕐 <b>Created At:</b> <code>" + blockedIp.CreatedAt.ToString("dd/MM/yyyy HH:mm:ss") + "</code>\n\n" +

                "✅ Admin có thể mở trang <b>Blocked IPs</b> để xem hoặc Unblock IP.";

            return message;
        }

        private static async Task SendMessageAsync(string message)
        {
            try
            {
                string botToken = GetBotToken();
                string chatId = GetChatId();

                if (string.IsNullOrWhiteSpace(botToken) ||
                    string.IsNullOrWhiteSpace(chatId))
                {
                    System.Diagnostics.Debug.WriteLine(
                        "[API Gateway Telegram] Missing bot token or chat id."
                    );
                    return;
                }

                string url = "https://api.telegram.org/bot" + botToken + "/sendMessage";

                string publicBaseUrl = ConfigurationManager.AppSettings["PublicBaseUrl"] ?? "";
                publicBaseUrl = publicBaseUrl.TrimEnd('/');

                object bodyObj;

                if (!string.IsNullOrWhiteSpace(publicBaseUrl))
                {
                    bodyObj = new
                    {
                        chat_id = chatId,
                        text = message,
                        parse_mode = "HTML",
                        disable_web_page_preview = true,
                        reply_markup = new
                        {
                            inline_keyboard = new[]
                            {
                new[]
                {
                    new
                    {
                        text = "🔓 Open Blocked IPs",
                        url = publicBaseUrl + "/Admin/BlockedIps"
                    }
                },
                new[]
                {
                    new
                    {
                        text = "📊 Open API Gateway Dashboard",
                        url = publicBaseUrl + "/Admin/ApiGatewayDashboard"
                    }
                }
            }
                        }
                    };
                }
                else
                {
                    bodyObj = new
                    {
                        chat_id = chatId,
                        text = message,
                        parse_mode = "HTML",
                        disable_web_page_preview = true
                    };
                }

                string json = JsonConvert.SerializeObject(bodyObj);

                using (var content = new StringContent(json, Encoding.UTF8, "application/json"))
                {
                    var response = await _httpClient.PostAsync(url, content);
                    string body = await response.Content.ReadAsStringAsync();

                    System.Diagnostics.Debug.WriteLine(
                        "[API Gateway Telegram] " + body
                    );
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway Telegram ERROR] " + ex.Message
                );
            }
        }

        private static bool IsEnabled()
        {
            string enabled = ConfigurationManager.AppSettings["ApiGatewayTelegramAlert.Enabled"];

            if (!string.IsNullOrWhiteSpace(enabled) &&
                enabled.Equals("false", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private static bool IsInCooldown(string key)
        {
            DateTime now = DateTime.Now;

            if (_lastAlertByKey.TryGetValue(key, out DateTime lastSent))
            {
                if ((now - lastSent).TotalSeconds < ALERT_COOLDOWN_SECONDS)
                {
                    return true;
                }
            }

            _lastAlertByKey[key] = now;
            return false;
        }

        private static string GetBotToken()
        {
            return ConfigurationManager.AppSettings["Telegram.BotToken"] ?? "";
        }

        private static string GetChatId()
        {
            return ConfigurationManager.AppSettings["Telegram.ChatId"] ?? "";
        }

        private static string H(string value)
        {
            return WebUtility.HtmlEncode(value ?? "");
        }
    }
}