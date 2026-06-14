using eParty.Areas.Admin.Models;
using eParty.Models;
using System;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace eParty.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class ApiGatewayLogsController : Controller
    {
        private readonly AppDbContext db = new AppDbContext();

        // GET: Admin/ApiGatewayLogs
        public async Task<ActionResult> Index(
            string ipAddress,
            string finalAction,
            string predictedLabel,
            string decisionSource,
            DateTime? fromDate,
            DateTime? toDate,
            int page = 1,
            int pageSize = 50
        )
        {
            if (page < 1)
            {
                page = 1;
            }

            if (pageSize < 10)
            {
                pageSize = 10;
            }

            if (pageSize > 200)
            {
                pageSize = 200;
            }

            IQueryable<ApiGatewayLog> query = db.ApiGatewayLogs.AsQueryable();

            query = ApplyFilters(
                query,
                ipAddress,
                finalAction,
                predictedLabel,
                decisionSource,
                fromDate,
                toDate
            );

            int totalItems = await query.CountAsync();

            int totalPages = (int)Math.Ceiling(totalItems / (double)pageSize);

            if (totalPages <= 0)
            {
                totalPages = 1;
            }

            if (page > totalPages)
            {
                page = totalPages;
            }

            var logs = await query
                .OrderByDescending(x => x.Id)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var model = new ApiGatewayLogListViewModel
            {
                Logs = logs,

                IpAddress = ipAddress,
                FinalAction = finalAction,
                PredictedLabel = predictedLabel,
                DecisionSource = decisionSource,
                FromDate = fromDate,
                ToDate = toDate,

                Page = page,
                PageSize = pageSize,
                TotalItems = totalItems,
                TotalPages = totalPages,

                TotalLogs = await db.ApiGatewayLogs.CountAsync(),
                FilteredLogs = totalItems,

                AllowCount = await query.CountAsync(x => x.FinalAction == "allow"),
                MonitorCount = await query.CountAsync(x => x.FinalAction == "monitor"),
                ChallengeCount = await query.CountAsync(x => x.FinalAction == "challenge_or_rate_limit"),
                BlockCount = await query.CountAsync(x => x.FinalAction == "block")
            };

            return View(model);
        }

        // GET: Admin/ApiGatewayLogs/Details/5
        public async Task<ActionResult> Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            ApiGatewayLog log = await db.ApiGatewayLogs.FindAsync(id);

            if (log == null)
            {
                return HttpNotFound();
            }

            return View(log);
        }

        // GET: Admin/ApiGatewayLogs/ExportCsv
        public async Task<FileResult> ExportCsv(
            string ipAddress,
            string finalAction,
            string predictedLabel,
            string decisionSource,
            DateTime? fromDate,
            DateTime? toDate
        )
        {
            IQueryable<ApiGatewayLog> query = db.ApiGatewayLogs.AsQueryable();

            query = ApplyFilters(
                query,
                ipAddress,
                finalAction,
                predictedLabel,
                decisionSource,
                fromDate,
                toDate
            );

            var logs = await query
                .OrderByDescending(x => x.Id)
                .Take(5000)
                .ToListAsync();

            var sb = new StringBuilder();

            sb.AppendLine(
                "Id,IpAddress,Controller,ActionName,RiskScore,PredictedLabel,FinalAction,DecisionSource,RequestRatePerMin,SequenceLength,GraphSelfLoops,CreatedAt"
            );

            foreach (var item in logs)
            {
                sb.AppendLine(string.Join(",",
                    item.Id,
                    Csv(item.IpAddress),
                    Csv(item.Controller),
                    Csv(item.ActionName),
                    item.RiskScore.ToString("0.0000"),
                    Csv(item.PredictedLabel),
                    Csv(item.FinalAction),
                    Csv(item.DecisionSource),
                    item.RequestRatePerMin.ToString("0.##"),
                    item.SequenceLength.ToString("0.##"),
                    item.GraphSelfLoops.ToString("0.##"),
                    Csv(item.CreatedAt.ToString("yyyy-MM-dd HH:mm:ss"))
                ));
            }

            byte[] bytes = new UTF8Encoding(true).GetBytes(sb.ToString());

            return File(
                bytes,
                "text/csv",
                "api_gateway_logs_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".csv"
            );
        }

        private IQueryable<ApiGatewayLog> ApplyFilters(
            IQueryable<ApiGatewayLog> query,
            string ipAddress,
            string finalAction,
            string predictedLabel,
            string decisionSource,
            DateTime? fromDate,
            DateTime? toDate
        )
        {
            if (!string.IsNullOrWhiteSpace(ipAddress))
            {
                query = query.Where(x => x.IpAddress.Contains(ipAddress));
            }

            if (!string.IsNullOrWhiteSpace(finalAction))
            {
                query = query.Where(x => x.FinalAction == finalAction);
            }

            if (!string.IsNullOrWhiteSpace(predictedLabel))
            {
                query = query.Where(x => x.PredictedLabel == predictedLabel);
            }

            if (!string.IsNullOrWhiteSpace(decisionSource))
            {
                query = query.Where(x => x.DecisionSource.Contains(decisionSource));
            }

            if (fromDate.HasValue)
            {
                DateTime from = fromDate.Value.Date;
                query = query.Where(x => x.CreatedAt >= from);
            }

            if (toDate.HasValue)
            {
                DateTime to = toDate.Value.Date.AddDays(1);
                query = query.Where(x => x.CreatedAt < to);
            }

            return query;
        }

        private string Csv(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return "\"\"";
            }

            return "\"" + value.Replace("\"", "\"\"") + "\"";
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