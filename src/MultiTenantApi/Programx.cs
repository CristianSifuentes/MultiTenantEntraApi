
//////using System.IdentityModel.Tokens.Jwt;
//////using System.Security.Claims;
//////using Microsoft.AspNetCore.Authentication.JwtBearer;
//////using Microsoft.IdentityModel.Tokens;
//////using MultiTenantApi.Security;

//////var builder = WebApplication.CreateBuilder(args);

//////// ---------- Config ----------
//////var azureAd = builder.Configuration.GetSection("AzureAd");
//////var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
//////var tenantId = azureAd["TenantId"] ?? "common";
//////var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

//////var audience = azureAd["Audience"] ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

//////// ---------- AuthN ----------
//////builder.Services
//////    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//////    .AddJwtBearer(options =>
//////    {
//////        options.Authority = authority;
//////        options.Audience = audience;

//////        // Important:
//////        // - Multi-tenant tokens have different issuers. We validate issuer using a tenant allow-list.
//////        // - We still validate signature and lifetime.
//////        options.TokenValidationParameters = new TokenValidationParameters
//////        {
//////            ValidateAudience = true,
//////            ValidAudience = audience,

//////            ValidateIssuer = true,
//////            //IssuerValidator = (IssuerValidator)TenantAllowListIssuerValidator.Build(builder.Configuration),
//////            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

//////            NameClaimType = "name",
//////            RoleClaimType = "roles" // app roles land here
//////        };

//////        // Helps when calling downstream APIs later; keep the original token.
//////        options.SaveToken = true;

//////        // Useful in dev when inspecting tokens:
//////        options.Events = new JwtBearerEvents
//////        {
//////            OnTokenValidated = ctx =>
//////            {
//////                // Normalize to avoid "JWT handler" mapping surprises.
//////                // We disable default inbound claim mapping at process-level too (below).
//////                return Task.CompletedTask;
//////            }
//////        };
//////    });

//////// Disable legacy claim type mapping so you see tid/scp/roles as-is.
//////JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

//////// ---------- AuthZ ----------
//////builder.Services.AddAuthorization(options =>
//////{
//////    AuthzPolicies.Configure(options, builder.Configuration);
//////});

//////// ---------- Swagger (OAuth2 optional) ----------
//////builder.Services.AddEndpointsApiExplorer();
//////builder.Services.AddSwaggerGen(o =>
//////{
//////    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi", Version = "v1" });

//////    // Optional: enable "Authorize" button in Swagger for auth code flows
//////    // (configure your swagger client app in Tenant B and set redirect URI)
//////    var clientId = azureAd["ClientId"] ?? "00000000-0000-0000-0000-000000000000";
//////    var authUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/authorize";
//////    var tokenUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/token";

//////    o.AddSecurityDefinition("oauth2", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
//////    {
//////        Type = Microsoft.OpenApi.Models.SecuritySchemeType.OAuth2,
//////        Flows = new Microsoft.OpenApi.Models.OpenApiOAuthFlows
//////        {
//////            AuthorizationCode = new Microsoft.OpenApi.Models.OpenApiOAuthFlow
//////            {
//////                AuthorizationUrl = new Uri(authUrl),
//////                TokenUrl = new Uri(tokenUrl),
//////                Scopes = new Dictionary<string, string>
//////                {
//////                    { $"{audience}/Documents.Read", "Read documents (delegated)" },
//////                    { $"{audience}/Reports.Read.All", "Read reports (admin delegated)" }
//////                }
//////            }
//////        }
//////    });

//////    o.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
//////    {
//////        {
//////            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
//////            {
//////                Reference = new Microsoft.OpenApi.Models.OpenApiReference
//////                {
//////                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
//////                    Id = "oauth2"
//////                }
//////            },
//////            new[] { $"{audience}/Documents.Read", $"{audience}/Reports.Read.All" }
//////        }
//////    });
//////});

//////var app = builder.Build();

//////app.UseSwagger();
//////app.UseSwaggerUI(c =>
//////{
//////    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi v1");
//////    c.OAuthClientId(builder.Configuration["Swagger:ClientId"] ?? ""); // optional
//////    c.OAuthUsePkce();
//////});

//////app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
//////   .AllowAnonymous();

//////app.MapGet("/auth/consent-callback", (HttpContext ctx) =>
//////{
//////    // This is a minimal redirect endpoint used by the admin-consent URL.
//////    // Entra will redirect here after admin consent.
//////    return Results.Ok(new
//////    {
//////        message = "Admin consent callback reached. You can close this tab.",
//////        query = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString())
//////    });
//////}).AllowAnonymous();

//////// Requires any Entra token that passes issuer + audience checks
//////app.MapGet("/whoami", (ClaimsPrincipal user) =>
//////{
//////    var tid = user.FindFirstValue("tid");
//////    var oid = user.FindFirstValue("oid");
//////    var upn = user.FindFirstValue("preferred_username") ?? user.FindFirstValue(ClaimTypes.Upn);
//////    var scopes = user.FindFirstValue("scp");
//////    var roles = user.FindAll("roles").Select(r => r.Value).ToArray();
//////    var azp = user.FindFirstValue("azp") ?? user.FindFirstValue("appid"); // client app id for v2/v1

//////    return Results.Ok(new
//////    {
//////        tenantId = tid,
//////        objectId = oid,
//////        user = user.Identity?.Name,
//////        preferredUsername = upn,
//////        clientAppId = azp,
//////        scp = scopes,
//////        roles
//////    });
//////})
//////.RequireAuthorization();

//////app.MapGet("/documents", (ClaimsPrincipal user) =>
//////{
//////    // Example “business data”
//////    var tid = user.FindFirstValue("tid");
//////    return Results.Ok(new
//////    {
//////        tenantId = tid,
//////        items = new[]
//////        {
//////            new { id = 1, title = "Entra Multi-tenant 101", classification = "Public" },
//////            new { id = 2, title = "Scopes vs App Roles", classification = "Internal" }
//////        }
//////    });
//////})
//////.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName);

//////app.MapGet("/reports", (ClaimsPrincipal user) =>
//////{
//////    var tid = user.FindFirstValue("tid");
//////    return Results.Ok(new
//////    {
//////        tenantId = tid,
//////        generatedAtUtc = DateTimeOffset.UtcNow,
//////        items = new[]
//////        {
//////            new { id = "RPT-001", title = "Monthly Usage", severity = "Info" },
//////            new { id = "RPT-002", title = "Security Audit", severity = "High" }
//////        }
//////    });
//////})
//////.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName);

//////app.UseHttpsRedirection();
//////app.UseAuthentication();
//////app.UseAuthorization();

//////app.Run();



//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;

//using Microsoft.AspNetCore.Authentication.JwtBearer;
//using Microsoft.AspNetCore.RateLimiting;
//using Microsoft.IdentityModel.Logging;
//using Microsoft.IdentityModel.Tokens;
//using Microsoft.OpenApi.Models;

//using Serilog;

//using Mapster;
//using MapsterMapper;

//using MultiTenantApi.Security;

//using MultiTenantApi.Mapping;
//using MultiTenantApi.Middleware;
//using MultiTenantApi.Models;
//using MultiTenantApi.Services;

//var builder = WebApplication.CreateBuilder(args);

//// =====================================================
//// Logging (Serilog) - from Class 2
//// =====================================================
//builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

//// =====================================================
//// Config (Multi-tenant) - from Class 1
//// =====================================================
//var azureAd = builder.Configuration.GetSection("AzureAd");
//var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
//var tenantId = azureAd["TenantId"] ?? "common"; // <-- multi-tenant by default
//var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

//var audience = azureAd["Audience"]
//    ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

//// Disable legacy claim type mapping so you see tid/scp/roles as-is.
//JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

//// =====================================================
//// AuthN (JWT Bearer) - MUST be like Class 1
//// =====================================================
//builder.Services
//    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.Authority = authority;
//        options.Audience = audience;

//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateAudience = true,
//            //ValidAudience = audience,

//             ValidAudiences = new[]
//             {
//                 audience,                    // api://58a207b2...
//                 azureAd["ClientId"]          // 58a207b2... (GUID)
//             },


//            // Multi-tenant issuer check via allow-list
//            ValidateIssuer = true,
//            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

//            NameClaimType = "name",
//            RoleClaimType = "roles" // app roles land here
//        };

//        options.SaveToken = true;

//        // Dev diagnostics (keep like Class 2 but without weakening validation)
//        IdentityModelEventSource.ShowPII = builder.Environment.IsDevelopment();

//        options.Events = new JwtBearerEvents
//        {
//            OnAuthenticationFailed = context =>
//            {
//                Log.Error(context.Exception,
//                    "JWT authentication failed. Authorization={AuthorizationHeader}",
//                    context.Request.Headers["Authorization"].ToString());
//                return Task.CompletedTask;
//            },
//            OnTokenValidated = context =>
//            {
//                var p = context.Principal;
//                var sub = p?.FindFirst("sub")?.Value;
//                var oid = p?.FindFirst("oid")?.Value;
//                var tid = p?.FindFirst("tid")?.Value;
//                var name = p?.Identity?.Name;
//                var roles = p?.FindAll("roles").Select(c => c.Value).ToArray() ?? Array.Empty<string>();
//                var scp = p?.FindFirst("scp")?.Value;

//                Log.Information("JWT validated. tid={Tid}, sub={Sub}, oid={Oid}, name={Name}, roles=[{Roles}], scp={Scp}",
//                    tid, sub, oid, name, string.Join(",", roles), scp);

//                return Task.CompletedTask;
//            },
//            OnChallenge = context =>
//            {
//                Log.Warning("JWT challenge. Error={Error}, Description={Description}",
//                    context.Error, context.ErrorDescription);
//                return Task.CompletedTask;
//            }
//        };
//    });

//// =====================================================
//// AuthZ - MUST be like Class 1 (central policies)
//// =====================================================
//builder.Services.AddAuthorization(options =>
//{
//    // Keep your “enterprise” policy pack centralized
//    AuthzPolicies.Configure(options, builder.Configuration);
//});

////builder.Services.AddAuthorization(options =>
////{
////    options.AddPolicy("AdminOnly", policy =>
////        policy.RequireRole("Admin"));
////});

//// =====================================================
//// Rate limiting - from Class 2
//// =====================================================
//builder.Services.AddRateLimiter(options =>
//{
//    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
//    options.AddFixedWindowLimiter("api", opt =>
//    {
//        opt.PermitLimit = 300;
//        opt.Window = TimeSpan.FromMinutes(1);
//    });
//});

//// =====================================================
//// Swagger - combine both worlds
//// - OAuth2 (Authorization Code) style from Class 1
//// - Bearer style from Class 2
//// =====================================================
//builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen(o =>
//{
//    o.SwaggerDoc("v1", new() { Title = "Unified MultiTenant API", Version = "v1" });

//    // (A) OAuth2 Authorization Code (optional)
//    var authUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/authorize";
//    var tokenUrl = $"{instance.TrimEnd('/')}/{tenantId}/oauth2/v2.0/token";

//    o.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
//    {
//        Type = SecuritySchemeType.OAuth2,
//        Flows = new OpenApiOAuthFlows
//        {
//            AuthorizationCode = new OpenApiOAuthFlow
//            {
//                AuthorizationUrl = new Uri(authUrl),
//                TokenUrl = new Uri(tokenUrl),
//                Scopes = new Dictionary<string, string>
//                {
//                    { $"{audience}/Documents.Read", "Read documents (delegated)" },
//                    { $"{audience}/Reports.Read.All", "Read reports (admin delegated)" }
//                }
//            }
//        }
//    });

//    // (B) Bearer token (for Postman / client_credentials)
//    o.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
//    {
//        Type = SecuritySchemeType.Http,
//        Scheme = "bearer",
//        BearerFormat = "JWT",
//        Description = "Azure AD / Entra ID Bearer token"
//    });

//    // Default requirement: either oauth2 or bearer
//    o.AddSecurityRequirement(new OpenApiSecurityRequirement
//    {
//        {
//            new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" } },
//            Array.Empty<string>()
//        }
//    });
//});

//// =====================================================
//// Mapster + Services - from Class 2
//// =====================================================
//MapsterConfig.RegisterMaps();
//builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
//builder.Services.AddSingleton<IMapper, ServiceMapper>();

//builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();
//builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>();

//var app = builder.Build();

//// =====================================================
//// Pipeline (enterprise order)
//// =====================================================
//app.UseMiddleware<EnforceHttpsMiddleware>();
//app.UseSerilogRequestLogging();

//app.UseRateLimiter();

//app.UseAuthentication();
//app.UseAuthorization();

//app.UseMiddleware<AuditMiddleware>();

//app.UseSwagger();
//app.UseSwaggerUI(c =>
//{
//    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Unified MultiTenant API v1");
//    c.OAuthClientId(builder.Configuration["Swagger:ClientId"] ?? "");
//    c.OAuthUsePkce();
//});

//// =====================================================
//// Endpoints (all coexist) - require RateLimit/Auth/OpenApi
//// =====================================================

//// ---- Health (public)
//app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
//   .AllowAnonymous()
//   .WithOpenApi();

//app.MapGet("/v1/health", () => Results.Ok(new { status = "ok" }))
//   .AllowAnonymous()
//   .WithOpenApi();

//// ---- Admin consent callback (public)
//app.MapGet("/auth/consent-callback", (HttpContext ctx) =>
//{
//    return Results.Ok(new
//    {
//        message = "Admin consent callback reached. You can close this tab.",
//        query = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString())
//    });
//})
//.AllowAnonymous()
//.WithOpenApi();

//// ---- Identity debug (any valid token)
//app.MapGet("/whoami", (ClaimsPrincipal user) =>
//{
//    var tid = user.FindFirstValue("tid");
//    var oid = user.FindFirstValue("oid");
//    var upn = user.FindFirstValue("preferred_username") ?? user.FindFirstValue(ClaimTypes.Upn);
//    var scopes = user.FindFirstValue("scp");
//    var roles = user.FindAll("roles").Select(r => r.Value).ToArray();
//    var azp = user.FindFirstValue("azp") ?? user.FindFirstValue("appid");

//    return Results.Ok(new
//    {
//        tenantId = tid,
//        objectId = oid,
//        user = user.Identity?.Name,
//        preferredUsername = upn,
//        clientAppId = azp,
//        scp = scopes,
//        roles
//    });
//})
//.RequireAuthorization()
//.RequireRateLimiting("api")
//.WithOpenApi();

//// ---- Documents (delegated scope policy from AuthzPolicies)
//app.MapGet("/documents", (ClaimsPrincipal user) =>
//{
//    var tid = user.FindFirstValue("tid");
//    return Results.Ok(new
//    {
//        tenantId = tid,
//        items = new[]
//        {
//            new { id = 1, title = "Entra Multi-tenant 101", classification = "Public" },
//            new { id = 2, title = "Scopes vs App Roles", classification = "Internal" }
//        }
//    });
//})
//.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
//.RequireRateLimiting("api")
//.WithOpenApi();

//// ---- Reports (app role policy from AuthzPolicies)
//app.MapGet("/reports", (ClaimsPrincipal user) =>
//{
//    var tid = user.FindFirstValue("tid");
//    return Results.Ok(new
//    {
//        tenantId = tid,
//        generatedAtUtc = DateTimeOffset.UtcNow,
//        items = new[]
//        {
//            new { id = "RPT-001", title = "Monthly Usage", severity = "Info" },
//            new { id = "RPT-002", title = "Security Audit", severity = "High" }
//        }
//    });
//})
//.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
//.RequireRateLimiting("api")
//.WithOpenApi();

//// ---- Raw data export (kept as in Class 2, but secured + rate limited)
//app.MapGet("/v1/raw-data", async (
//    HttpContext http,
//    [AsParameters] RawQuery q,
//    IRawDataService dataSvc) =>
//{
//    var take = Math.Min(q.Limit is > 0 ? q.Limit.Value : 100, 100);
//    var page = await dataSvc.QueryAsync(q.Filter, q.NextPageToken, take, http.RequestAborted);

//    var items = page.Items.Select(r =>
//    {
//        var shape = FieldProjector.ToApiShape(r);
//        shape["syntheticId"] = SyntheticId.Create("raw", r.InternalId.ToString());
//        return shape;
//    });

//    return Results.Ok(new
//    {
//        items,
//        page = new
//        {
//            limit = take,
//            nextPageToken = page.NextToken,
//            count = page.Items.Count
//        }
//    });
//})
//.RequireRateLimiting("api")
//.RequireAuthorization() // keep baseline auth (multi-tenant validated)
//.Produces(StatusCodes.Status200OK)
//.ProducesProblem(StatusCodes.Status401Unauthorized)
//.ProducesProblem(StatusCodes.Status403Forbidden)
//.ProducesProblem(StatusCodes.Status429TooManyRequests)
//.WithOpenApi();

//// ---- Call records export (use your AuthzPolicies to enforce Admin/Role/Scope properly)
//app.MapGet("/v1/export/call-records", async (
//    ICallRecordService svc,
//    IMapper mapper,
//    CancellationToken ct) =>
//{
//    var records = await svc.GetSampleAsync(ct);
//    var dto = mapper.Map<List<CallRecordExportDto>>(records);

//    return Results.Ok(new
//    {
//        items = dto,
//        count = dto.Count
//    });
//})
//.RequireRateLimiting("api")
//.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName) // <- choose your preferred policy
//.WithOpenApi();

//// ---- Metadata endpoint (same rule set)
//app.MapGet("/v1/export/metadata/call-records", async (
//    ICallRecordService svc,
//    IMapper mapper,
//    CancellationToken ct) =>
//{
//    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();

//    var sampleDomain = await svc.GetSampleAsync(ct);
//    var sampleExport = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

//    var response = new EntityMetadataResponse<CallRecordExportDto>(
//        EntityName: "CallRecord",
//        Version: "v1",
//        Fields: fields,
//        Sample: sampleExport);

//    return Results.Ok(response);
//})
//.RequireRateLimiting("api")
////.RequireAuthorization("AdminOnly")
////.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName) // <- choose your preferred policy
//.WithOpenApi();

//app.Run();

//public record RawQuery(string? Filter, int? Limit, string? NextPageToken);
