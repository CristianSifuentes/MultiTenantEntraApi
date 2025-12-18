using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace MultiTenantApi.Middleware;

public sealed class AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        // Investigation best practice for security
        var sw = Stopwatch.StartNew();
        await next(context);
        sw.Stop();

        var user = context.User?.Identity?.Name
                   ?? context.User?.FindFirst("oid")?.Value
                   ?? "anonymous";

        logger.LogInformation(
            "EXPORT {User} {Method} {Path} {Status} {Elapsed}ms",
            user,
            context.Request.Method,
            context.Request.Path,
            context.Response.StatusCode,
            sw.ElapsedMilliseconds);
    }
}
