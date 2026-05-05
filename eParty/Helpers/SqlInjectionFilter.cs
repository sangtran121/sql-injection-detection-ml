using eParty.Models;
using System;
using System.Data.Entity;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace eParty.Helpers
{
    public class SqlInjectionFilter : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            var request = filterContext.HttpContext.Request;
            string suspiciousInput = GetSuspiciousInput(request);

            if (!string.IsNullOrEmpty(suspiciousInput))
            {
                LogToDatabase(filterContext, suspiciousInput);
                HandleSuspiciousRequest(filterContext);
                return;
            }

            base.OnActionExecuting(filterContext);
        }

        private string GetSuspiciousInput(HttpRequestBase request)
        {
            foreach (var key in request.Form.AllKeys)
            {
                if (IsSuspicious(request.Form[key])) return request.Form[key];
            }

            foreach (var key in request.QueryString.AllKeys)
            {
                if (IsSuspicious(request.QueryString[key])) return request.QueryString[key];
            }

            foreach (var value in request.RequestContext.RouteData.Values.Values)
            {
                if (IsSuspicious(value?.ToString())) return value?.ToString();
            }

            return null;
        }

        private bool IsSuspicious(string input)
        {
            if (string.IsNullOrWhiteSpace(input) || input.Length < 3) return false;
            string lower = input.ToLower();

            var patterns = new[] { "or 1=1", "'1'='1", "union select", "drop table", "pg_sleep",
                                  "waitfor delay", "information_schema", "xp_cmdshell", "exec(",
                                  "cast((select", "@@version", "/**/", "/*!'" };

            foreach (var p in patterns)
                if (lower.Contains(p)) return true;

            return false;
        }

        private void LogToDatabase(ActionExecutingContext filterContext, string suspiciousInput)
        {
            try
            {
                using (var db = new AppDbContext())
                {
                    var log = new SQLInjectionLog
                    {
                        IpAddress = filterContext.HttpContext.Request.UserHostAddress,
                        Url = filterContext.HttpContext.Request.RawUrl,
                        SuspiciousInput = suspiciousInput,
                        Controller = filterContext.RouteData.Values["controller"]?.ToString(),
                        Action = filterContext.RouteData.Values["action"]?.ToString(),
                        UserAgent = filterContext.HttpContext.Request.UserAgent,
                        IsBlocked = true
                    };

                    db.SQLInjectionLogs.Add(log);
                    db.SaveChanges();
                }
            }
            catch { /* Bỏ qua lỗi log */ }
        }

        private void HandleSuspiciousRequest(ActionExecutingContext filterContext)
        {
            filterContext.Result = new JsonResult
            {
                Data = new { success = false, message = "Yêu cầu bị chặn vì nghi ngờ SQL Injection!", code = "SQL_INJECTION_DETECTED" },
                JsonRequestBehavior = JsonRequestBehavior.AllowGet
            };

            filterContext.HttpContext.Response.StatusCode = 403;
        }
    }
}