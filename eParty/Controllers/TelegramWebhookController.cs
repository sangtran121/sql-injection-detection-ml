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

            // Xử lý callback_data khi admin bấm nút
            if (update?.callback_query != null)
            {
                string callbackData = update.callback_query.data?.ToString();
                long callbackQueryId = update.callback_query.id;

                if (callbackData != null && callbackData.StartsWith("whitelist:"))
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

                            // Trả lời callback để Telegram biết đã xử lý
                            TelegramHelper.AnswerCallback(callbackQueryId.ToString(), "✅ Đã whitelist thành công!");
                        }
                        else
                        {
                            TelegramHelper.AnswerCallback(callbackQueryId.ToString(), "⚠️ Token không tồn tại hoặc đã dùng.");
                        }
                    }
                }
            }

            return new HttpStatusCodeResult(200);
        }
    }
}