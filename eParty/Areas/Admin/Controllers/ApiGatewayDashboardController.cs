using eParty.Areas.Admin.Models;
using eParty.Models;
using System;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace eParty.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class ApiGatewayDashboardController : Controller
    {
        private readonly eParty.Service.ApiGatewayMlService mlService =
            new eParty.Service.ApiGatewayMlService();
        private readonly AppDbContext db = new AppDbContext();

        // GET: Admin/ApiGatewayDashboard
        public async Task<ActionResult> Index()
        {
            DateTime now = DateTime.Now;
            DateTime today = DateTime.Today;
            DateTime last24h = now.AddHours(-24);

            var query = db.ApiGatewayLogs.AsQueryable();

            var logsLast24h = await query
                .Where(x => x.CreatedAt >= last24h)
                .ToListAsync();

            int totalLogs = await query.CountAsync();

            var model = new ApiGatewayDashboardViewModel
            {
                TotalLogs = totalLogs,
                TodayLogs = await query.CountAsync(x => x.CreatedAt >= today),
                Last24hLogs = logsLast24h.Count,

                AllowCount = logsLast24h.Count(x => x.FinalAction == "allow"),
                MonitorCount = logsLast24h.Count(x => x.FinalAction == "monitor"),
                ChallengeCount = logsLast24h.Count(x => x.FinalAction == "challenge_or_rate_limit"),
                BlockCount = logsLast24h.Count(x => x.FinalAction == "block"),

                ActiveBlockedIpCount = await db.BlockedIps.CountAsync(x =>
                    x.IsActive && x.BlockedUntil > now
                ),

                TotalBlockedIpCount = await db.BlockedIps.CountAsync(),

                NormalCount = logsLast24h.Count(x => x.PredictedLabel == "normal"),
                AbnormalCount = logsLast24h.Count(x => x.PredictedLabel == "abnormal"),

                AverageRiskScore = logsLast24h.Any() ? logsLast24h.Average(x => x.RiskScore) : 0,
                MaxRiskScore = logsLast24h.Any() ? logsLast24h.Max(x => x.RiskScore) : 0,

                RecentLogs = await query
                    .OrderByDescending(x => x.Id)
                    .Take(15)
                    .ToListAsync()
            };

            BuildHourlyChart(model, logsLast24h, now);
            BuildActionChart(model);
            BuildTopIpChart(model, logsLast24h);
            BuildTopRouteChart(model, logsLast24h);

            var health = await mlService.CheckHealthAsync();

            model.MlServiceOnline = health.IsOnline;
            model.MlServiceStatus = health.Status;
            model.MlModelType = health.ModelType;
            model.MlFeatureCount = health.Features != null ? health.Features.Count : 0;
            model.MlErrorMessage = health.ErrorMessage;

            return View(model);
        }

        private void BuildHourlyChart(
            ApiGatewayDashboardViewModel model,
            System.Collections.Generic.List<ApiGatewayLog> logs,
            DateTime now
        )
        {
            DateTime currentHour = new DateTime(
                now.Year,
                now.Month,
                now.Day,
                now.Hour,
                0,
                0
            );

            for (int i = 23; i >= 0; i--)
            {
                DateTime start = currentHour.AddHours(-i);
                DateTime end = start.AddHours(1);

                var hourLogs = logs
                    .Where(x => x.CreatedAt >= start && x.CreatedAt < end)
                    .ToList();

                model.HourLabels.Add(start.ToString("HH:mm"));

                model.HourAllowCounts.Add(hourLogs.Count(x => x.FinalAction == "allow"));
                model.HourMonitorCounts.Add(hourLogs.Count(x => x.FinalAction == "monitor"));
                model.HourChallengeCounts.Add(hourLogs.Count(x => x.FinalAction == "challenge_or_rate_limit"));
                model.HourBlockCounts.Add(hourLogs.Count(x => x.FinalAction == "block"));
            }
        }

        private void BuildActionChart(ApiGatewayDashboardViewModel model)
        {
            model.ActionLabels.Add("Allow");
            model.ActionCounts.Add(model.AllowCount);

            model.ActionLabels.Add("Monitor");
            model.ActionCounts.Add(model.MonitorCount);

            model.ActionLabels.Add("Rate Limit");
            model.ActionCounts.Add(model.ChallengeCount);

            model.ActionLabels.Add("Block");
            model.ActionCounts.Add(model.BlockCount);
        }

        private void BuildTopIpChart(
            ApiGatewayDashboardViewModel model,
            System.Collections.Generic.List<ApiGatewayLog> logs
        )
        {
            var topIps = logs
                .GroupBy(x => string.IsNullOrEmpty(x.IpAddress) ? "unknown" : x.IpAddress)
                .Select(g => new
                {
                    Ip = g.Key,
                    Count = g.Count()
                })
                .OrderByDescending(x => x.Count)
                .Take(5)
                .ToList();

            foreach (var item in topIps)
            {
                model.TopIpLabels.Add(item.Ip);
                model.TopIpCounts.Add(item.Count);
            }
        }

        private void BuildTopRouteChart(
            ApiGatewayDashboardViewModel model,
            System.Collections.Generic.List<ApiGatewayLog> logs
        )
        {
            var topRoutes = logs
                .GroupBy(x => (x.Controller ?? "Unknown") + "/" + (x.ActionName ?? "Unknown"))
                .Select(g => new
                {
                    Route = g.Key,
                    Count = g.Count()
                })
                .OrderByDescending(x => x.Count)
                .Take(5)
                .ToList();

            foreach (var item in topRoutes)
            {
                model.TopRouteLabels.Add(item.Route);
                model.TopRouteCounts.Add(item.Count);
            }
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