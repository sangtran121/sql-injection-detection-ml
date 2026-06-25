using eParty.Models;
using eParty.Service;
using System;
using System.Web.Mvc;

namespace eParty.Helpers
{
    /// <summary>
    /// Global MVC Filter cho API Gateway ML.
    ///
    /// Nhiệm vụ:
    /// - Chạy trước mỗi Action MVC
    /// - Gọi ApiGatewaySecurityService để tính feature + gọi Flask ML
    /// - Xử lý action Flask trả về:
    ///     allow                  -> cho qua
    ///     monitor                -> cho qua nhưng ghi log debug
    ///     challenge_or_rate_limit -> trả HTTP 429
    ///     block                  -> trả HTTP 403
    ///
    /// Lưu ý:
    /// - File này KHÔNG tự train model
    /// - File này KHÔNG tính feature trực tiếp
    /// - Feature nằm trong ApiGatewaySecurityService
    /// </summary>
    public class ApiGatewayMlFilter : ActionFilterAttribute
    {
        private static readonly ApiGatewaySecurityService _securityService =
            new ApiGatewaySecurityService();

        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (filterContext == null)
            {
                return;
            }

            try
            {
                if (ShouldSkip(filterContext))
                {
                    base.OnActionExecuting(filterContext);
                    return;
                }

                ApiGatewayMlResult result = _securityService
                    .EvaluateAsync(filterContext.HttpContext)
                    .GetAwaiter()
                    .GetResult();

                if (result == null)
                {
                    base.OnActionExecuting(filterContext);
                    return;
                }

                WriteDebugLog(filterContext, result);

                string action = (result.Action ?? "allow").ToLowerInvariant();

                switch (action)
                {
                    case "allow":
                        base.OnActionExecuting(filterContext);
                        return;

                    case "monitor":
                        // Monitor nghĩa là ghi nhận bất thường nhưng vẫn cho request đi tiếp.
                        base.OnActionExecuting(filterContext);
                        return;

                    case "challenge_or_rate_limit":
                        HandleChallengeOrRateLimit(filterContext, result);
                        return;

                    case "block":
                        HandleBlock(filterContext, result);
                        return;

                    default:
                        // Nếu Flask trả action lạ thì an toàn cho website: cho qua.
                        System.Diagnostics.Debug.WriteLine(
                            "[API Gateway Filter] Unknown action: " + action
                        );

                        base.OnActionExecuting(filterContext);
                        return;
                }
            }
            catch (Exception ex)
            {
                // Tuyệt đối không để filter làm sập website.
                System.Diagnostics.Debug.WriteLine(
                    "[API Gateway Filter] Exception: " + ex.Message
                );

                base.OnActionExecuting(filterContext);
            }
        }

        /// <summary>
        /// Bỏ qua các request không cần kiểm tra API Gateway ML.
        /// Các route quản trị bảo mật / log / whitelist phải được bỏ qua
        /// để tránh vòng lặp tự chặn chính hệ thống bảo mật.
        /// </summary>
        private bool ShouldSkip(ActionExecutingContext filterContext)
        {
            try
            {
                if (filterContext.IsChildAction)
                {
                    return true;
                }

                string controller = GetRouteValue(filterContext, "controller");
                string action = GetRouteValue(filterContext, "action");

                if (string.IsNullOrWhiteSpace(controller))
                {
                    return true;
                }

                controller = controller.ToLowerInvariant();
                action = (action ?? "").ToLowerInvariant();

                // Không kiểm tra trang lỗi để tránh vòng lặp lỗi.
                if (controller == "error")
                {
                    return true;
                }

                // Bỏ qua các controller của chính hệ thống API Gateway.
                // Nếu không skip, admin có thể bị chặn khi đang xem log / dashboard / unblock IP.
                if (
                    controller == "apigatewaylogs" ||
                    controller == "apigatewaydashboard" ||
                    controller == "blockedips" ||
                    controller == "apigatewaymodelcomparison"
                )
                {
                    return true;
                }

                // Bỏ qua module SQL Injection review/whitelist.
                // Route như SQLInjectionLog/CheckWhitelisted polling liên tục sau khi user báo cáo sai.
                // Nếu API Gateway kiểm tra route này, nó sẽ tự tạo rate cao và block nhầm admin/user.
                if (controller == "sqlinjectionlog")
                {
                    return true;
                }

                // Bỏ qua login/logout/register để tránh trường hợp redirect ReturnUrl hoặc login flow bị rate-limit.
                if (controller == "account")
                {
                    return true;
                }

                // Bỏ qua các file tĩnh nếu có request đi qua MVC route.
                if (
                    controller == "content" ||
                    controller == "scripts" ||
                    controller == "bundles"
                )
                {
                    return true;
                }

                return false;
            }
            catch
            {
                // Nếu lỗi khi đọc route thì cho qua để filter không làm sập website.
                return true;
            }
        }

        /// <summary>
        /// Xử lý challenge/rate-limit.
        /// Trả HTTP 429.
        /// </summary>
        /// <summary>
        /// Xử lý challenge/rate-limit.
        /// Trả HTTP 429.
        /// </summary>
        private void HandleChallengeOrRateLimit(
            ActionExecutingContext filterContext,
            ApiGatewayMlResult result
        )
        {
            var response = filterContext.HttpContext.Response;

            response.StatusCode = 429;
            response.TrySkipIisCustomErrors = true;

            string message =
                "Yêu cầu của bạn đang được giới hạn tạm thời bởi API Gateway Security. " +
                "Vui lòng thử lại sau vài giây.";

            if (IsAjaxRequest(filterContext))
            {
                filterContext.Result = new JsonResult
                {
                    JsonRequestBehavior = JsonRequestBehavior.AllowGet,
                    Data = new
                    {
                        success = false,
                        blocked = false,
                        action = "challenge_or_rate_limit",
                        message = message,
                        risk_score = Math.Round(result.RiskScore, 4),
                        predicted_label = result.PredictedLabel,
                        decision_source = result.DecisionSource
                    }
                };

                return;
            }

            string controller = GetRouteValue(filterContext, "controller");
            string actionName = GetRouteValue(filterContext, "action");
            string route = controller + "/" + actionName;
            string ip = GetClientIp(filterContext);

            ShowApiGatewayBlockedPage(
                filterContext,
                result,
                ip,
                route,
                429
            );
        }

        /// <summary>
        /// Xử lý block cứng.
        /// Trả HTTP 403.
        /// </summary>
        /// <summary>
        /// Xử lý block cứng.
        /// Trả HTTP 403.
        /// </summary>
        private void HandleBlock(
            ActionExecutingContext filterContext,
            ApiGatewayMlResult result
        )
        {
            var response = filterContext.HttpContext.Response;

            response.StatusCode = 403;
            response.TrySkipIisCustomErrors = true;

            string message =
                "Yêu cầu đã bị chặn bởi API Gateway Security vì có dấu hiệu tấn công.";

            if (IsAjaxRequest(filterContext))
            {
                filterContext.Result = new JsonResult
                {
                    JsonRequestBehavior = JsonRequestBehavior.AllowGet,
                    Data = new
                    {
                        success = false,
                        blocked = true,
                        action = "block",
                        message = message,
                        risk_score = Math.Round(result.RiskScore, 4),
                        predicted_label = result.PredictedLabel,
                        decision_source = result.DecisionSource
                    }
                };

                return;
            }

            string controller = GetRouteValue(filterContext, "controller");
            string actionName = GetRouteValue(filterContext, "action");
            string route = controller + "/" + actionName;
            string ip = GetClientIp(filterContext);

            ShowApiGatewayBlockedPage(
                filterContext,
                result,
                ip,
                route,
                403
            );
        }

        /// <summary>
        /// Ghi log debug ra Output window của Visual Studio.
        /// </summary>
        private void WriteDebugLog(
            ActionExecutingContext filterContext,
            ApiGatewayMlResult result
        )
        {
            try
            {
                string controller = GetRouteValue(filterContext, "controller");
                string actionName = GetRouteValue(filterContext, "action");
                string ip = GetClientIp(filterContext);

                string emoji = "✅";

                if (result.Action == "monitor")
                {
                    emoji = "👁️";
                }
                else if (result.Action == "challenge_or_rate_limit")
                {
                    emoji = "⚠️";
                }
                else if (result.Action == "block")
                {
                    emoji = "🚫";
                }

                System.Diagnostics.Debug.WriteLine(
                    string.Format(
                        "[API Gateway Filter] {0} {1}/{2} IP={3} Label={4} Risk={5:F4} Action={6} Source={7}",
                        emoji,
                        controller,
                        actionName,
                        ip,
                        result.PredictedLabel,
                        result.RiskScore,
                        result.Action,
                        result.DecisionSource
                    )
                );
            }
            catch
            {
                // ignored
            }
        }
        private void ShowApiGatewayBlockedPage(
            ActionExecutingContext filterContext,
            ApiGatewayMlResult result,
            string ipAddress,
            string route,
            int statusCode)
        {
            if (filterContext == null)
            {
                return;
            }

            if (result == null)
            {
                result = ApiGatewayMlResult.Allow("fallback_empty_result");
            }

            string title = statusCode == 403
                ? "IP của bạn đang bị khóa tạm thời"
                : "Yêu cầu của bạn bị giới hạn";

            string message = statusCode == 403
                ? "API Gateway phát hiện hành vi truy cập bất thường lặp lại và đã tạm thời khóa IP."
                : "API Gateway phát hiện tần suất truy cập bất thường và đã giới hạn yêu cầu này.";

            var viewData = new ViewDataDictionary();

            viewData["Title"] = title;
            viewData["Message"] = message;
            viewData["IpAddress"] = string.IsNullOrWhiteSpace(ipAddress) ? "unknown" : ipAddress;
            viewData["Route"] = string.IsNullOrWhiteSpace(route) ? "unknown" : route;
            viewData["RiskScore"] = result.RiskScore.ToString("0.0000");
            viewData["PredictedLabel"] = result.PredictedLabel ?? "unknown";
            viewData["DecisionSource"] = result.DecisionSource ?? "unknown";
            viewData["FinalAction"] = result.Action ?? "unknown";
            viewData["StatusCode"] = statusCode;

            filterContext.HttpContext.Response.StatusCode = statusCode;
            filterContext.Result = new ViewResult
            {
                ViewName = "~/Views/Shared/ApiGatewayBlocked.cshtml",
                ViewData = viewData
            };
        }

        private bool IsAjaxRequest(ActionExecutingContext filterContext)
        {
            try
            {
                return filterContext.HttpContext.Request.IsAjaxRequest();
            }
            catch
            {
                return false;
            }
        }

        private string GetRouteValue(ActionExecutingContext filterContext, string key)
        {
            try
            {
                object value = filterContext.RouteData.Values[key];

                if (value == null)
                {
                    return "";
                }

                return Convert.ToString(value);
            }
            catch
            {
                return "";
            }
        }

        private string GetClientIp(ActionExecutingContext filterContext)
        {
            try
            {
                string forwarded = filterContext.HttpContext.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];

                if (!string.IsNullOrWhiteSpace(forwarded))
                {
                    return forwarded.Split(',')[0].Trim();
                }

                string realIp = filterContext.HttpContext.Request.ServerVariables["HTTP_X_REAL_IP"];

                if (!string.IsNullOrWhiteSpace(realIp))
                {
                    return realIp.Trim();
                }

                string userHostAddress = filterContext.HttpContext.Request.UserHostAddress;

                if (!string.IsNullOrWhiteSpace(userHostAddress))
                {
                    return userHostAddress.Trim();
                }
            }
            catch
            {
                // ignored
            }

            return "unknown";
        }
    }
}