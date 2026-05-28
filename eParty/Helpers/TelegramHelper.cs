using eParty.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace eParty.Helpers
{
    public static class TelegramHelper
    {
        private static readonly string BotToken = "8859783946:AAGToRsMaTgWvbHKbmyYnY6IzyxU-zO6ogU";
        private static readonly string ChatId = "6343263182";

        // ================== RATE LIMIT: 1 IP chỉ gửi 1 lần/phút ==================
        private static readonly ConcurrentDictionary<string, DateTime> _lastSentByIp
            = new ConcurrentDictionary<string, DateTime>();

        public static bool IsRateLimited(string ip)
        {
            if (_lastSentByIp.TryGetValue(ip, out DateTime lastSent))
            {
                if ((DateTime.Now - lastSent).TotalSeconds < 60)
                    return true; // vẫn trong cooldown 60 giây
            }
            _lastSentByIp[ip] = DateTime.Now;
            return false;
        }

        // ================== GỬI ALERT + TRẢ VỀ MESSAGE ID ==================
        public static async Task<long> SendAlert(string payload, string ip, string time, string token)
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

                    if (response.IsSuccessStatusCode)
                    {
                        // Trích message_id từ response để lưu lại
                        dynamic parsed = JsonConvert.DeserializeObject(respBody);
                        long messageId = parsed?.result?.message_id ?? 0;
                        return messageId;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("[Telegram ERROR] " + ex.Message);
            }

            return 0;
        }

        // ================== SỬA TIN NHẮN KHI WHITELIST ==================
        public static void EditMessageWhitelisted(long messageId, string ip)
        {
            try
            {
                string newText = $"✅ *Đã WHITELIST thành công!*\n\n" +
                                 $"🌐 *IP báo cáo:* `{ip}`\n" +
                                 $"🕐 *Duyệt lúc:* {DateTime.Now:dd/MM/yyyy HH:mm:ss}\n\n" +
                                 $"_Payload này đã được thêm vào whitelist._";

                var bodyObj = new
                {
                    chat_id = ChatId,
                    message_id = messageId,
                    text = newText,
                    parse_mode = "Markdown"
                    // Không có reply_markup → nút bị xóa tự động
                };

                using (var client = new HttpClient())
                {
                    string url = $"https://api.telegram.org/bot{BotToken}/editMessageText";
                    var content = new StringContent(
                        JsonConvert.SerializeObject(bodyObj),
                        Encoding.UTF8,
                        "application/json");
                    client.PostAsync(url, content).Wait();
                }
            }
            catch { }
        }

        // ================== XÓA TIN NHẮN KHI BỎ QUA ==================
        public static void DeleteMessage(long messageId)
        {
            try
            {
                var bodyObj = new
                {
                    chat_id = ChatId,
                    message_id = messageId
                };

                using (var client = new HttpClient())
                {
                    string url = $"https://api.telegram.org/bot{BotToken}/deleteMessage";
                    var content = new StringContent(
                        JsonConvert.SerializeObject(bodyObj),
                        Encoding.UTF8,
                        "application/json");
                    client.PostAsync(url, content).Wait();
                }
            }
            catch { }
        }

        // ================== TRẢ LỜI CALLBACK ==================
        public static void AnswerCallback(string callbackQueryId, string text)
        {
            try
            {
                using (var client = new HttpClient())
                {
                    string url = $"https://api.telegram.org/bot{BotToken}/answerCallbackQuery";
                    var body = new { callback_query_id = callbackQueryId, text = text, show_alert = false };
                    var content = new StringContent(
                        JsonConvert.SerializeObject(body),
                        Encoding.UTF8,
                        "application/json");
                    client.PostAsync(url, content).Wait();
                }
            }
            catch { }
        }
    }
}