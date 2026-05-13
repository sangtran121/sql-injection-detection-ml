using System;
using System.Linq;
using System.Web.Mvc;
using eParty.Models;

namespace eParty.Controllers
{
    [Authorize(Roles = "Admin")]   // Chỉ Admin mới xem được
    public class SQLInjectionLogController : Controller
    {
        private AppDbContext db = new AppDbContext();

        public ActionResult Index()
        {
            var logs = db.SQLInjectionLogs
                         .OrderByDescending(l => l.Timestamp)
                         .Take(100)        // Lấy 100 log mới nhất
                         .ToList();

            return View(logs);
        }
    }
}