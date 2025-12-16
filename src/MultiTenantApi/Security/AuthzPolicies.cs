using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;

namespace MultiTenantApi.Security;

internal static class AuthzPolicies
{
    public const string DocumentsReadPolicyName = "Documents.Read";
    public const string ReportsReadPolicyName = "Reports.Read";

    public static void Configure(AuthorizationOptions options, IConfiguration config)
    {
        var docsScope = config["AuthZ:DocumentsReadScope"] ?? "Documents.Read";
        var reportsScope = config["AuthZ:ReportsReadAllScope"] ?? "Reports.Read.All";
        var reportsRole = config["AuthZ:ReportsReadAllAppRole"] ?? "Reports.Read.All";

        // Delegated scope policy
        options.AddPolicy(DocumentsReadPolicyName, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireAssertion(ctx => ctx.User.HasScope(docsScope));
        });

        // Reports can be accessed either by:
        // - delegated scope (scp) OR
        // - app-only role (roles)
        options.AddPolicy(ReportsReadPolicyName, policy =>
        {
            policy.RequireAuthenticatedUser();
            policy.RequireAssertion(ctx =>
                ctx.User.HasScope(reportsScope) || ctx.User.HasAppRole(reportsRole));
        });
    }
}
