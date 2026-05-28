using eParty.Helpers;
using eParty.Models;
using System;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace eParty.Controllers
{
    [Authorize(Roles = "Admin")]
    public class SQLInjectionLogController : Controller
    {
        private AppDbContext db = new AppDbContext();

        public ActionResult Index(string filter = "all")
        {
            var logs = db.SQLInjectionLogs
                         .OrderByDescending(l => l.Timestamp)
                         .AsQueryable();

            // Lọc theo loại
            if (filter == "rule")
                logs = logs.Where(l => l.DetectedBy != null && l.DetectedBy.Contains("Rule"));
            else if (filter == "ml")
                logs = logs.Where(l => l.DetectedBy != null && l.DetectedBy.Contains("ML"));
            else if (filter == "blocked")
                logs = logs.Where(l => l.IsBlocked);

            var model = logs.Take(100).ToList();   // Giới hạn 100 log mới nhất

            ViewBag.CurrentFilter = filter;

            return View(model);
        }

        // ====================== XÓA LOG ======================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id)
        {
            var log = db.SQLInjectionLogs.Find(id);
            if (log != null)
            {
                db.SQLInjectionLogs.Remove(log);
                db.SaveChanges();
                TempData["Success"] = "Đã xóa log thành công!";
            }
            return RedirectToAction("Index");
        }

        // ====================== WHITELIST PAYLOAD ======================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult AddToWhitelist(int id)
        {
            var log = db.SQLInjectionLogs.Find(id);
            if (log != null && !string.IsNullOrWhiteSpace(log.SuspiciousInput))
            {
                SqlInjectionFilter.AddToWhitelist(log.SuspiciousInput);
                TempData["Success"] = "✅ Payload đã được thêm vào Whitelist thành công!";
            }
            return RedirectToAction("Index");
        }
   

        // Admin bấm link trong Telegram → whitelist
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public ActionResult WhitelistByToken(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                TempData["Error"] = "❌ Token không hợp lệ.";
                return RedirectToAction("Index");
            }

            var pending = db.PendingWhitelists
                            .FirstOrDefault(p => p.Token == token && !p.IsUsed);

            if (pending == null)
            {
                TempData["Error"] = "❌ Token không tồn tại hoặc đã được dùng.";
                return RedirectToAction("Index");
            }

            SqlInjectionFilter.AddToWhitelist(pending.Payload);
            pending.IsUsed = true;
            db.SaveChanges();

            TempData["Success"] = "✅ Payload đã được WHITELIST thành công!";
            return RedirectToAction("Index");
        }
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public ActionResult WhitelistFromReport(string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                TempData["Error"] = "❌ Payload không hợp lệ.";
                return RedirectToAction("Index");
            }

            SqlInjectionFilter.AddToWhitelist(payload);

            TempData["Success"] = "✅ Payload đã được WHITELIST thành công! Hệ thống sẽ cho qua payload này từ bây giờ.";

            return RedirectToAction("Index");
        }
        // Nhận token từ View, gửi Telegram

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ReportFalsePositive(string token)
        {
            if (string.IsNullOrEmpty(token))
                return Json(new { success = false, reason = "no_token" }, JsonRequestBehavior.AllowGet);

            string ip = HttpContext.Request.UserHostAddress ?? "Unknown";

            // ================== RATE LIMIT ==================
            if (TelegramHelper.IsRateLimited(ip))
            {
                return Json(new { success = false, reason = "rate_limited" }, JsonRequestBehavior.AllowGet);
            }

            using (var db = new AppDbContext())
            {
                var pending = db.PendingWhitelists.FirstOrDefault(p => p.Token == token && !p.IsUsed);
                if (pending == null)
                    return Json(new { success = false, reason = "not_found" }, JsonRequestBehavior.AllowGet);

                string time = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss");

                // SendAlert giờ trả về messageId
                long messageId = await TelegramHelper.SendAlert(pending.Payload, ip, time, token);

                if (messageId > 0)
                {
                    // Lưu messageId vào DB để sau này edit/xóa
                    pending.TelegramMessageId = messageId;
                    db.SaveChanges();
                }

                return Json(new { success = messageId > 0 }, JsonRequestBehavior.AllowGet);
            }
        }

        // Polling: kiểm tra xem token đã được whitelist chưa
        [HttpGet]
        [AllowAnonymous]
        public ActionResult CheckWhitelisted(string token)
        {
            if (string.IsNullOrEmpty(token))
                return Json(new { whitelisted = false }, JsonRequestBehavior.AllowGet);

            using (var db = new AppDbContext())
            {
                var pending = db.PendingWhitelists.FirstOrDefault(p => p.Token == token);
                bool whitelisted = pending != null && pending.IsUsed;
                return Json(new { whitelisted }, JsonRequestBehavior.AllowGet);
            }
        }
    }


}