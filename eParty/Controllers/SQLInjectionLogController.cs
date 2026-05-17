using eParty.Helpers;
using eParty.Models;
using System;
using System.Linq;
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
    }
}