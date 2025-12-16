using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MultiTenantApi.Security;

var builder = WebApplication.CreateBuilder(args);

// ---------- Config ----------
var azureAd = builder.Configuration.GetSection("AzureAd");
var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
var tenantId = azureAd["TenantId"] ?? "common";
var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

var audience = azureAd["Audience"] ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

// ---------- AuthN ----------
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;

        // Important:
        // - Multi-tenant tokens have different issuers. We validate issuer using a tenant allow-list.
        // - We still validate signature and lifetime.
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudience = audience,

            ValidateIssuer = true,
            //IssuerValidator = (IssuerValidator)TenantAllowListIssuerValidator.Build(builder.Configuration),
            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

            NameClaimType = "name",
            RoleClaimType = "roles" // app roles land here
        };

        // Helps when calling downstream APIs later; keep the original token.
        options.SaveToken = true;

        // Useful in dev when inspecting tokens:
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                // Normalize to avoid "JWT handler" mapping surprises.
                // We disable default inbound claim mapping at process-level too (below).
                return Task.CompletedTask;
            }
        };
    });

// Disable legacy claim type mapping so you see tid/scp/roles as-is.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// ---------- AuthZ ----------
builder.Services.AddAuthorization(options =>
{
    AuthzPolicies.Configure(options, builder.Configuration);
});

// ---------- Swagger (OAuth2 optional) ----------
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi", Version = "v1" });

    // Optional: enable "Authorize" button in Swagger for auth code flows
    // (configure your swagger client app in Tenant B and set redirect URI)
    var clientId = azureAd["ClientId"] ?? "00000000-0000-0000-0000-000000000000";
    var authUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/authorize";
    var tokenUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/token";

    o.AddSecurityDefinition("oauth2", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.OAuth2,
        Flows = new Microsoft.OpenApi.Models.OpenApiOAuthFlows
        {
            AuthorizationCode = new Microsoft.OpenApi.Models.OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri(authUrl),
                TokenUrl = new Uri(tokenUrl),
                Scopes = new Dictionary<string, string>
                {
                    { $"{audience}/Documents.Read", "Read documents (delegated)" },
                    { $"{audience}/Reports.Read.All", "Read reports (admin delegated)" }
                }
            }
        }
    });

    o.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "oauth2"
                }
            },
            new[] { $"{audience}/Documents.Read", $"{audience}/Reports.Read.All" }
        }
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi v1");
    c.OAuthClientId(builder.Configuration["Swagger:ClientId"] ?? ""); // optional
    c.OAuthUsePkce();
});

app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
   .AllowAnonymous();

app.MapGet("/auth/consent-callback", (HttpContext ctx) =>
{
    // This is a minimal redirect endpoint used by the admin-consent URL.
    // Entra will redirect here after admin consent.
    return Results.Ok(new
    {
        message = "Admin consent callback reached. You can close this tab.",
        query = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString())
    });
}).AllowAnonymous();

// Requires any Entra token that passes issuer + audience checks
app.MapGet("/whoami", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    var oid = user.FindFirstValue("oid");
    var upn = user.FindFirstValue("preferred_username") ?? user.FindFirstValue(ClaimTypes.Upn);
    var scopes = user.FindFirstValue("scp");
    var roles = user.FindAll("roles").Select(r => r.Value).ToArray();
    var azp = user.FindFirstValue("azp") ?? user.FindFirstValue("appid"); // client app id for v2/v1

    return Results.Ok(new
    {
        tenantId = tid,
        objectId = oid,
        user = user.Identity?.Name,
        preferredUsername = upn,
        clientAppId = azp,
        scp = scopes,
        roles
    });
})
.RequireAuthorization();

app.MapGet("/documents", (ClaimsPrincipal user) =>
{
    // Example “business data”
    var tid = user.FindFirstValue("tid");
    return Results.Ok(new
    {
        tenantId = tid,
        items = new[]
        {
            new { id = 1, title = "Entra Multi-tenant 101", classification = "Public" },
            new { id = 2, title = "Scopes vs App Roles", classification = "Internal" }
        }
    });
})
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName);

app.MapGet("/reports", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    return Results.Ok(new
    {
        tenantId = tid,
        generatedAtUtc = DateTimeOffset.UtcNow,
        items = new[]
        {
            new { id = "RPT-001", title = "Monthly Usage", severity = "Info" },
            new { id = "RPT-002", title = "Security Audit", severity = "High" }
        }
    });
})
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName);

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.Run();
