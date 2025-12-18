using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

using Mapster;
using MapsterMapper;

using MultiTenantApi.Security;

// ⬇️ Estos namespaces deben existir en tu solución
// Ajusta si tus carpetas/namespaces se llaman distinto:
using MultiTenantApi.Mapping;
using MultiTenantApi.Middleware;
using MultiTenantApi.Models;
using MultiTenantApi.Services;

var builder = WebApplication.CreateBuilder(args);

// =====================================================
// Config (Multi-tenant) - KEEP AS IS
// =====================================================
var azureAd = builder.Configuration.GetSection("AzureAd");
var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
var tenantId = azureAd["TenantId"] ?? "common";
var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

var audience = azureAd["Audience"]
    ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

// Disable legacy claim type mapping so you see tid/scp/roles as-is.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// =====================================================
// AuthN - KEEP AS IS (multi-tenant allow-list)
// + small hardening (ValidAudiences)
// =====================================================
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = true,
            ValidAudiences = new[]
            {
                audience,              // api://{clientId}
                azureAd["ClientId"]    // {clientId} (GUID) - helps Postman/tools
            },

            ValidateIssuer = true,
            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

            NameClaimType = "name",
            RoleClaimType = "roles"
        };

        options.SaveToken = true;

        // Dev diagnostics (optional but useful while fixing auth)
        IdentityModelEventSource.ShowPII = builder.Environment.IsDevelopment();

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = ctx =>
            {
                // ⚠️ Do not log full tokens in prod.
                // Here we log only header presence in dev.
                return Task.CompletedTask;
            },
            OnTokenValidated = ctx =>
            {
                // Keep your existing no-op
                return Task.CompletedTask;
            },
            OnChallenge = ctx =>
            {
                return Task.CompletedTask;
            }
        };
    });

// =====================================================
// AuthZ - KEEP AS IS
// + Add AdminOnly policy needed by /v1/export/metadata/call-records
// =====================================================
builder.Services.AddAuthorization(options =>
{
    AuthzPolicies.Configure(options, builder.Configuration);

    // ✅ Needed for the new endpoint (same as your export API)
    // If your tokens use a different role name, adjust here:
    options.AddPolicy("AdminOnly", p =>
    {
        p.RequireAuthenticatedUser();
        p.RequireRole("Admin");
    });
});

// =====================================================
// Rate limiting - REQUIRED by the new endpoint
// =====================================================
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddFixedWindowLimiter("api", opt =>
    {
        opt.PermitLimit = 300;
        opt.Window = TimeSpan.FromMinutes(1);
    });
});

// =====================================================
// Swagger - KEEP AS IS + add bearerAuth for Postman
// =====================================================
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi", Version = "v1" });

    // OAuth2 Authorization Code (optional)
    var authUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/authorize";
    var tokenUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/token";

    o.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            AuthorizationCode = new OpenApiOAuthFlow
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

    // ✅ Bearer (Postman)
    o.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "Azure AD / Entra ID Bearer token"
    });

    // Default: bearerAuth (you can still use oauth2 in Swagger if configured)
    o.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" }
            },
            Array.Empty<string>()
        }
    });
});

// =====================================================
// ✅ Mapster + Domain Services REQUIRED for /v1/export/metadata/call-records
// =====================================================

// Register Mapster mappings (must exist in MultiTenantApi.Mapping)
MapsterConfig.RegisterMaps();

// register global settings used by ServiceMapper
builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
builder.Services.AddSingleton<IMapper, ServiceMapper>();

// Services used by endpoints (must exist in MultiTenantApi.Services)
builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();       // optional if you later add /v1/raw-data
builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>(); // ✅ required by metadata endpoint

var app = builder.Build();

// =====================================================
// Pipeline
// =====================================================

// If these middleware exist in your project, keep them.
// If they do NOT exist, comment out these lines.
app.UseMiddleware<EnforceHttpsMiddleware>();
app.UseMiddleware<AuditMiddleware>();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi v1");
    c.OAuthClientId(builder.Configuration["Swagger:ClientId"] ?? "");
    c.OAuthUsePkce();
});

app.UseHttpsRedirection();

app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

// =====================================================
// Existing endpoints - KEEP INTACT
// =====================================================

app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
   .AllowAnonymous()
   .WithOpenApi();

app.MapGet("/auth/consent-callback", (HttpContext ctx) =>
{
    return Results.Ok(new
    {
        message = "Admin consent callback reached. You can close this tab.",
        query = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString())
    });
}).AllowAnonymous()
  .WithOpenApi();

app.MapGet("/whoami", (ClaimsPrincipal user) =>
{
    var tid = user.FindFirstValue("tid");
    var oid = user.FindFirstValue("oid");
    var upn = user.FindFirstValue("preferred_username") ?? user.FindFirstValue(ClaimTypes.Upn);
    var scopes = user.FindFirstValue("scp");
    var roles = user.FindAll("roles").Select(r => r.Value).ToArray();
    var azp = user.FindFirstValue("azp") ?? user.FindFirstValue("appid");

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
.RequireAuthorization()
.WithOpenApi();

app.MapGet("/documents", (ClaimsPrincipal user) =>
{
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
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.WithOpenApi();

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
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.WithOpenApi();


// =====================================================
// ✅ NEW endpoint: /v1/export/metadata/call-records
// Professional add: RateLimit + AdminOnly + OpenAPI
// =====================================================

// ---- Raw data export (kept as in Class 2, but secured + rate limited)
app.MapGet("/raw-data", async (
    HttpContext http,
    [AsParameters] RawQuery q,
    IRawDataService dataSvc) =>
{
    var take = Math.Min(q.Limit is > 0 ? q.Limit.Value : 100, 100);
    var page = await dataSvc.QueryAsync(q.Filter, q.NextPageToken, take, http.RequestAborted);

    var items = page.Items.Select(r =>
    {
        var shape = FieldProjector.ToApiShape(r);
        shape["syntheticId"] = SyntheticId.Create("raw", r.InternalId.ToString());
        return shape;
    });

    return Results.Ok(new
    {
        items,
        page = new
        {
            limit = take,
            nextPageToken = page.NextToken,
            count = page.Items.Count
        }
    });
})
.RequireRateLimiting("api")
.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
.Produces(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();




app.MapGet("/export/metadata/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct) =>
{
    // Build field-level metadata (from attributes) - must exist in MultiTenantApi.Models
    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();

    // Provide a sample payload (already mapped to safe DTO)
    var sampleDomain = await svc.GetSampleAsync(ct);
    var sampleExport = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

    var response = new EntityMetadataResponse<CallRecordExportDto>(
        EntityName: "CallRecord",
        Version: "v1",
        Fields: fields,
        Sample: sampleExport);

    return Results.Ok(response);
})
.RequireRateLimiting("api")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
.Produces<EntityMetadataResponse<CallRecordExportDto>>(StatusCodes.Status200OK)
.ProducesProblem(StatusCodes.Status401Unauthorized)
.ProducesProblem(StatusCodes.Status403Forbidden)
.ProducesProblem(StatusCodes.Status429TooManyRequests)
.WithOpenApi();


//// ---- Call records export (use your AuthzPolicies to enforce Admin/Role/Scope properly)
app.MapGet("/export/call-records", async (
    ICallRecordService svc,
    IMapper mapper,
    CancellationToken ct) =>
{
    var records = await svc.GetSampleAsync(ct);
    var dto = mapper.Map<List<CallRecordExportDto>>(records);

    return Results.Ok(new
    {
        items = dto,
        count = dto.Count
    });
})
.RequireRateLimiting("api")
.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName) // <- choose your preferred policy
.WithOpenApi();


app.Run();

public record RawQuery(string? Filter, int? Limit, string? NextPageToken);


