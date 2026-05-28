using eParty.Helpers;
using eParty.Models;
using Newtonsoft.Json;
using System.IO;
using System.Linq;
using System.Web.Mvc;

namespace eParty.Controllers
{
    public class TelegramWebhookController : Controller
    {
        [HttpPost]
        [AllowAnonymous]
        public ActionResult Index()
        {
            string body = new StreamReader(Request.InputStream).ReadToEnd();
            dynamic update = JsonConvert.DeserializeObject(body);

            if (update?.callback_query != null)
            {
                string callbackData = update.callback_query.data?.ToString();
                string callbackQueryId = update.callback_query.id?.ToString();
                string senderName = update.callback_query.from?.first_name?.ToString() ?? "Admin";

                if (callbackData == null) return new HttpStatusCodeResult(200);

                if (callbackData.StartsWith("whitelist:"))
                {
                    string token = callbackData.Replace("whitelist:", "");

                    using (var db = new AppDbContext())
                    {
                        var pending = db.PendingWhitelists
                                        .FirstOrDefault(p => p.Token == token && !p.IsUsed);

                        if (pending != null)
                        {
                            SqlInjectionFilter.AddToWhitelist(pending.Payload);
                            pending.IsUsed = true;
                            db.SaveChanges();

                            // ✅ Hiện toast "Đã whitelist!" cho admin
                            TelegramHelper.AnswerCallback(callbackQueryId, "✅ Đã whitelist thành công!");

                            // ✅ Edit tin nhắn gốc → hiện trạng thái đã duyệt, xóa 2 nút
                            if (pending.TelegramMessageId > 0)
                                TelegramHelper.EditMessageWhitelisted(pending.TelegramMessageId, pending.Payload.Length > 80
                                    ? pending.Payload.Substring(0, 80) + "..."
                                    : pending.Payload);
                        }
                        else
                        {
                            TelegramHelper.AnswerCallback(callbackQueryId, "⚠️ Token không tồn tại hoặc đã dùng.");
                        }
                    }
                }
                else if (callbackData.StartsWith("ignore:"))
                {
                    string token = callbackData.Replace("ignore:", "");

                    using (var db = new AppDbContext())
                    {
                        var pending = db.PendingWhitelists
                                        .FirstOrDefault(p => p.Token == token);

                        // ❌ Toast nhanh cho admin
                        TelegramHelper.AnswerCallback(callbackQueryId, "🗑️ Đã bỏ qua và xóa báo cáo.");

                        // ❌ Xóa tin nhắn khỏi Telegram
                        if (pending?.TelegramMessageId > 0)
                            TelegramHelper.DeleteMessage(pending.TelegramMessageId);
                    }
                }
            }

            return new HttpStatusCodeResult(200);
        }
    }
}