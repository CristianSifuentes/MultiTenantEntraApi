using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace MultiTenantApi.Security;

/// <summary>
/// Validates token issuer for multi-tenant scenarios using a tenant allow-list.
/// 
/// Why this exists:
/// - In multi-tenant Entra ID, issuer changes per tenant:
///   https://login.microsoftonline.com/{tid}/v2.0
/// - Setting ValidateIssuer=false is convenient but dangerous (any tenant can call you).
/// - This validator enforces: token.tid must be in AllowedTenants unless AllowAnyTenant=true.
/// </summary>
//internal static class TenantAllowListIssuerValidator
//{
//    public static Func<string, SecurityToken, TokenValidationParameters, string> Build(IConfiguration config)
//    {
//        var allowAny = config.GetValue("Tenancy:AllowAnyTenant", false);
//        var allowed = config.GetSection("Tenancy:AllowedTenants").Get<string[]>() ?? Array.Empty<string>();

//        var allowedSet = new HashSet<string>(allowed.Where(x => !string.IsNullOrWhiteSpace(x)),
//            StringComparer.OrdinalIgnoreCase);

//        return (issuer, token, parameters) =>
//        {
//            if (token is not JwtSecurityToken jwt)
//                throw new SecurityTokenInvalidIssuerException("Token is not a JWT.");

//            var tid = jwt.Claims.FirstOrDefault(c => c.Type == "tid")?.Value;
//            if (string.IsNullOrWhiteSpace(tid))
//                throw new SecurityTokenInvalidIssuerException("Missing 'tid' claim.");

//            if (!allowAny && !allowedSet.Contains(tid))
//                throw new SecurityTokenInvalidIssuerException($"Tenant '{tid}' is not allowed.");

//            // We accept the issuer as provided by metadata validation. Returning issuer tells the handler it's valid.
//            return issuer;
//        };
//    }
//}


internal static class TenantAllowListIssuerValidator
{
    public static IssuerValidator Build(IConfiguration config)
    {
        var allowAny = config.GetValue("Tenancy:AllowAnyTenant", false);
        var allowed = config.GetSection("Tenancy:AllowedTenants").Get<string[]>() ?? Array.Empty<string>();

        var allowedSet = new HashSet<string>(
            allowed.Where(x => !string.IsNullOrWhiteSpace(x)),
            StringComparer.OrdinalIgnoreCase);

        return (issuer, token, parameters) =>
        {
            if (token is not JwtSecurityToken jwt)
                throw new SecurityTokenInvalidIssuerException("Token is not a JWT.");

            var tid = jwt.Claims.FirstOrDefault(c => c.Type == "tid")?.Value;
            if (string.IsNullOrWhiteSpace(tid))
                throw new SecurityTokenInvalidIssuerException("Missing 'tid' claim.");

            if (!allowAny && !allowedSet.Contains(tid))
                throw new SecurityTokenInvalidIssuerException($"Tenant '{tid}' is not allowed.");

            return issuer;
        };
    }
}