using Microsoft.AspNetCore.Http;

namespace MultiTenantApi.Middleware;

public sealed class EnforceHttpsMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (!context.Request.IsHttps)
        {
            var host = context.Request.Host;
            var path = context.Request.Path + context.Request.QueryString;
            var httpsUrl = $"https://{host}{path}";
            context.Response.Redirect(httpsUrl, permanent: false);
            return;
        }

        await next(context);
    }
}
