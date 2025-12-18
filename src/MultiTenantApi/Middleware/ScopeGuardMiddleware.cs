using Serilog;

public class ScopeGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _requiredScope;
    private readonly string[] _forbiddenScopes;

    public ScopeGuardMiddleware(RequestDelegate next, string requiredScope, params string[] forbiddenScopes)
    {
        _next = next;
        _requiredScope = requiredScope;
        _forbiddenScopes = forbiddenScopes ?? Array.Empty<string>();
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var user = context.User;

        // Si no está autenticado, deja que lo maneje Auth / [Authorize]
        if (user?.Identity?.IsAuthenticated != true)
        {
            await _next(context);
            return;
        }

        var scp = user.FindFirst("scp")?.Value;

        if (string.IsNullOrWhiteSpace(scp))
        {
            Log.Warning("ScopeGuard: authenticated user but no 'scp' claim present. Path = {Path}", context.Request.Path);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "forbidden",
                reason = "Token has no 'scp' claim"
            });
            return;
        }

        var scopes = scp.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!scopes.Contains(_requiredScope))
        {
            Log.Warning("ScopeGuard: required scope '{RequiredScope}' missing. Token scopes = {Scopes}", _requiredScope, string.Join(" ", scopes));
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "forbidden",
                reason = $"Required scope '{_requiredScope}' is missing"
            });
            return;
        }

        if (_forbiddenScopes.Any(fs => scopes.Contains(fs)))
        {
            Log.Warning("ScopeGuard: forbidden scope present. Forbidden = {Forbidden}, Token scopes = {Scopes}",
                string.Join(",", _forbiddenScopes),
                string.Join(" ", scopes));

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "forbidden",
                reason = "Token has forbidden scopes"
            });
            return;
        }

        // ✅ Todo bien, sigue pipeline
        await _next(context);
    }
}

// Extension method
public static class ScopeGuardMiddlewareExtensions
{
    public static IApplicationBuilder UseScopeGuard(
        this IApplicationBuilder app,
        string requiredScope,
        params string[] forbiddenScopes)
    {
        return app.UseMiddleware<ScopeGuardMiddleware>(requiredScope, forbiddenScopes);
    }
}
