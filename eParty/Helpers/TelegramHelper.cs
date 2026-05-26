using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace eParty.Helpers
{
    public static class TelegramHelper
    {
        private static readonly string BotToken = "8859783946:AAGToRsMaTgWvbHKbmyYnY6IzyxU-zO6ogU";
        private static readonly string ChatId = "6343263182";

        public static async Task<bool> SendAlert(string payload, string ip, string time, string token)
        {
            try
            {
                string safePayload = payload.Replace("`", "'");
                if (safePayload.Length > 800)
                    safePayload = safePayload.Substring(0, 800) + "\n...";

                string message = $"🚨 *False Positive Report*\n\n" +
                                 $"📋 *Payload đầy đủ:*\n```\n{safePayload}\n```\n\n" +
                                 $"🌐 *IP:* `{ip}`\n" +
                                 $"🕐 *Thời gian:* {time}";

                var bodyObj = new
                {
                    chat_id = ChatId,
                    text = message,
                    parse_mode = "Markdown",
                    reply_markup = new
                    {
                        inline_keyboard = new object[][]
                        {
                    new object[]
                    {
                        new { text = "✅ Whitelist payload này", callback_data = $"whitelist:{token}" },
                        new { text = "❌ Bỏ qua",               callback_data = $"ignore:{token}"   }
                    }
                        }
                    }
                };

                using (var client = new HttpClient())
                {
                    string url = $"https://api.telegram.org/bot{BotToken}/sendMessage";
                    var content = new StringContent(
                        JsonConvert.SerializeObject(bodyObj),
                        Encoding.UTF8,
                        "application/json");

                    var response = await client.PostAsync(url, content);
                    string respBody = await response.Content.ReadAsStringAsync();
                    System.Diagnostics.Debug.WriteLine("[Telegram] " + respBody);
                    return response.IsSuccessStatusCode;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("[Telegram ERROR] " + ex.Message);
                return false;
            }
        }

        // Trả lời callback để nút không bị loading mãi
        public static void AnswerCallback(string callbackQueryId, string text)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    string url = $"https://api.telegram.org/bot{BotToken}/answerCallbackQuery";
                    var body = new { callback_query_id = callbackQueryId, text = text };
                    var content = new StringContent(
                        JsonConvert.SerializeObject(body),
                        Encoding.UTF8,
                        "application/json");
                    client.PostAsync(url, content).Wait();
                }
            }
            catch { }
        }

        private static string SavePendingWhitelist(string payload)
        {
            string token = Guid.NewGuid().ToString("N").Substring(0, 12);
            using (var db = new AppDbContext())
            {
                db.PendingWhitelists.Add(new PendingWhitelist
                {
                    Payload = payload,
                    Token = token,
                    CreatedAt = DateTime.Now,
                    IsUsed = false
                });
                db.SaveChanges();
            }
            return token;
        }
    }
}