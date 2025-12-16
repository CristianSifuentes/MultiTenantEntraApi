using System.Security.Claims;

namespace MultiTenantApi.Security;

internal static class ClaimsExtensions
{
    public static bool HasScope(this ClaimsPrincipal user, string scope)
    {
        var scp = user.FindFirstValue("scp");
        if (string.IsNullOrWhiteSpace(scp)) return false;

        // scp is space-delimited in Entra v2 tokens
        return scp.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                  .Any(s => string.Equals(s, scope, StringComparison.OrdinalIgnoreCase));
    }

    public static bool HasAppRole(this ClaimsPrincipal user, string role)
    {
        return user.FindAll("roles")
                   .Any(r => string.Equals(r.Value, role, StringComparison.OrdinalIgnoreCase));
    }
}
