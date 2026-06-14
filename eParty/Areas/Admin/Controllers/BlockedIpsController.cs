using eParty.Models;
using System;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace eParty.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class BlockedIpsController : Controller
    {
        private readonly AppDbContext db = new AppDbContext();

        // GET: Admin/BlockedIps
        public async Task<ActionResult> Index(bool showAll = false)
        {
            DateTime now = DateTime.Now;

            var query = db.BlockedIps.AsQueryable();

            if (!showAll)
            {
                query = query.Where(x => x.IsActive && x.BlockedUntil > now);
            }

            var blockedIps = await query
                .OrderByDescending(x => x.Id)
                .ToListAsync();

            ViewBag.ShowAll = showAll;

            return View(blockedIps);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Unblock(int id)
        {
            var blockedIp = await db.BlockedIps.FindAsync(id);

            if (blockedIp == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.NotFound);
            }

            blockedIp.IsActive = false;
            blockedIp.UnblockedAt = DateTime.Now;
            blockedIp.LastUpdatedAt = DateTime.Now;

            await db.SaveChangesAsync();

            return RedirectToAction("Index");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DeleteExpired()
        {
            DateTime now = DateTime.Now;

            var expiredItems = await db.BlockedIps
                .Where(x => !x.IsActive || x.BlockedUntil <= now)
                .ToListAsync();

            db.BlockedIps.RemoveRange(expiredItems);

            await db.SaveChangesAsync();

            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}