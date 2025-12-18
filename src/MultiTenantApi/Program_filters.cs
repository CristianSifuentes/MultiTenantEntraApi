//using System.IdentityModel.Tokens.Jwt;
//using System.Reflection;
//using System.Security.Claims;

//using Microsoft.AspNetCore.Authentication.JwtBearer;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.RateLimiting;
//using Microsoft.IdentityModel.Logging;
//using Microsoft.IdentityModel.Tokens;
//using Microsoft.OpenApi.Models;

//using Mapster;
//using MapsterMapper;

//using MultiTenantApi.Security;

//// ⬇️ Estos namespaces deben existir en tu solución
//using MultiTenantApi.Mapping;
//using MultiTenantApi.Middleware;
//using MultiTenantApi.Models;
//using MultiTenantApi.Services;

//var builder = WebApplication.CreateBuilder(args);

//// =====================================================
//// Config (Multi-tenant) - KEEP AS IS
//// =====================================================
//var azureAd = builder.Configuration.GetSection("AzureAd");
//var instance = azureAd["Instance"] ?? "https://login.microsoftonline.com/";
//var tenantId = azureAd["TenantId"] ?? "common";
//var authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";

//var audience = azureAd["Audience"]
//    ?? throw new InvalidOperationException("AzureAd:Audience is required (e.g., api://{API_CLIENT_ID}).");

//// Disable legacy claim type mapping so you see tid/scp/roles as-is.
//JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

//// =====================================================
//// AuthN - KEEP AS IS (multi-tenant allow-list)
//// + small hardening (ValidAudiences)
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
//            ValidAudiences = new[]
//            {
//                audience,              // api://{clientId}
//                azureAd["ClientId"]    // {clientId} (GUID) - helps Postman/tools
//            },

//            ValidateIssuer = true,
//            IssuerValidator = TenantAllowListIssuerValidator.Build(builder.Configuration),

//            NameClaimType = "name",
//            RoleClaimType = "roles"
//        };

//        options.SaveToken = true;

//        IdentityModelEventSource.ShowPII = builder.Environment.IsDevelopment();

//        options.Events = new JwtBearerEvents
//        {
//            OnAuthenticationFailed = _ => Task.CompletedTask,
//            OnTokenValidated = _ => Task.CompletedTask,
//            OnChallenge = _ => Task.CompletedTask
//        };
//    });

//// =====================================================
//// AuthZ - KEEP AS IS
//// + Add AdminOnly policy
//// =====================================================
//builder.Services.AddAuthorization(options =>
//{
//    AuthzPolicies.Configure(options, builder.Configuration);

//    options.AddPolicy("AdminOnly", p =>
//    {
//        p.RequireAuthenticatedUser();
//        p.RequireRole("Admin");
//    });
//});

//// =====================================================
//// Rate limiting - REQUIRED by endpoints
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
//// Swagger - KEEP AS IS + add bearerAuth for Postman
//// =====================================================
//builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen(o =>
//{
//    o.SwaggerDoc("v1", new() { Title = "MultiTenantApi", Version = "v1" });

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

//    o.AddSecurityDefinition("bearerAuth", new OpenApiSecurityScheme
//    {
//        Type = SecuritySchemeType.Http,
//        Scheme = "bearer",
//        BearerFormat = "JWT",
//        Description = "Azure AD / Entra ID Bearer token"
//    });

//    o.AddSecurityRequirement(new OpenApiSecurityRequirement
//    {
//        {
//            new OpenApiSecurityScheme
//            {
//                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "bearerAuth" }
//            },
//            Array.Empty<string>()
//        }
//    });
//});

//// =====================================================
//// Mapster + Services REQUIRED for export endpoints
//// =====================================================
//MapsterConfig.RegisterMaps();
//builder.Services.AddSingleton(TypeAdapterConfig.GlobalSettings);
//builder.Services.AddSingleton<IMapper, ServiceMapper>();

//builder.Services.AddSingleton<IRawDataService, InMemoryRawDataService>();
//builder.Services.AddSingleton<ICallRecordService, InMemoryCallRecordService>();

//var app = builder.Build();

//// =====================================================
//// Pipeline
//// =====================================================
//app.UseMiddleware<EnforceHttpsMiddleware>();
//app.UseMiddleware<AuditMiddleware>();

//app.UseSwagger();
//app.UseSwaggerUI(c =>
//{
//    c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenantApi v1");
//    c.OAuthClientId(builder.Configuration["Swagger:ClientId"] ?? "");
//    c.OAuthUsePkce();
//});

//app.UseHttpsRedirection();
//app.UseRateLimiter();
//app.UseAuthentication();
//app.UseAuthorization();

//// =====================================================
//// Existing endpoints - KEEP INTACT
//// =====================================================
//app.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }))
//   .AllowAnonymous()
//   .WithOpenApi();

//app.MapGet("/auth/consent-callback", (HttpContext ctx) =>
//{
//    return Results.Ok(new
//    {
//        message = "Admin consent callback reached. You can close this tab.",
//        query = ctx.Request.Query.ToDictionary(k => k.Key, v => v.Value.ToString())
//    });
//}).AllowAnonymous()
//  .WithOpenApi();

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
//.WithOpenApi();

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
//.WithOpenApi();

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
//.WithOpenApi();

//// =====================================================
//// /raw-data (KEEP INTACT)
//// =====================================================
//app.MapGet("/raw-data", async (
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
//.RequireAuthorization(AuthzPolicies.DocumentsReadPolicyName)
//.Produces(StatusCodes.Status200OK)
//.ProducesProblem(StatusCodes.Status401Unauthorized)
//.ProducesProblem(StatusCodes.Status403Forbidden)
//.ProducesProblem(StatusCodes.Status429TooManyRequests)
//.WithOpenApi();

//// =====================================================
//// ✅ NEW: Filters for /export/metadata/call-records using [AsParameters]
//// =====================================================
//app.MapGet("/export/metadata/call-records", async (
//    [AsParameters] CallRecordsMetadataQuery q,
//    ICallRecordService svc,
//    IMapper mapper,
//    CancellationToken ct) =>
//{
//    // 1) Build metadata
//    var fields = ApiMetadataBuilder.BuildFor<CallRecord>();


//    // 2) Apply field selection + filtering + sorting (safe, whitelist-ish)
//    var filteredFields = MetadataQueryEngine.Apply(fields, q);

//    // 3) Sample (optional, bounded)
//    List<CallRecordExportDto>? sample = null;
//    if (q.IncludeSample)
//    {
//        var sampleDomain = await svc.GetSampleAsync(ct);
//        sample = mapper.Map<List<CallRecordExportDto>>(sampleDomain);

//        if (q.SampleLimit is > 0)
//            sample = sample.Take(Math.Min(q.SampleLimit.Value, 50)).ToList();
//    }

//    var response = new
//    {
//        entityName = "CallRecord",
//        version = "v1",
//        query = new
//        {
//            q.Fields,
//            q.Filter,
//            q.Sort,
//            q.SortDir,
//            includeSample = q.IncludeSample,
//            sampleLimit = q.SampleLimit
//        },
//        fields = filteredFields,
//        sample
//    };

//    return Results.Ok(response);
//})
//.RequireRateLimiting("api")
//.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
//.Produces(StatusCodes.Status200OK)
//.ProducesProblem(StatusCodes.Status401Unauthorized)
//.ProducesProblem(StatusCodes.Status403Forbidden)
//.ProducesProblem(StatusCodes.Status429TooManyRequests)
//.WithOpenApi();

//// =====================================================
//// /export/call-records (KEEP INTACT, but you can also add filters later)
//// =====================================================
//app.MapGet("/export/call-records", async (
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
//.RequireAuthorization(AuthzPolicies.ReportsReadPolicyName)
//.WithOpenApi();

//app.Run();

//// =====================================================
//// Query records
//// =====================================================
//public record RawQuery(string? Filter, int? Limit, string? NextPageToken);

//// =====================================================
//// ✅ Query object for metadata endpoint (AsParameters)
//// =====================================================
//// Ejemplos:
////  /export/metadata/call-records?fields=timestamp,callerId,calleeId
////  /export/metadata/call-records?filter=masked eq true
////  /export/metadata/call-records?filter=name contains 'user'&sort=name&sortDir=asc
////  /export/metadata/call-records?includeSample=false
//public sealed record CallRecordsMetadataQuery(
//    string? Filter = null,
//    string? Fields = null,
//    string? Sort = null,
//    string? SortDir = null,
//    bool IncludeSample = true,
//    int? SampleLimit = 10);

//// =====================================================
//// ✅ “Impresionante” engine para filtrar metadata sin acoplarte
//// - Soporta mini OData-like (eq / contains) pero con reglas controladas
//// - Whitelist implícita: solo Name/Masked/Pii/Classification
//// =====================================================
//internal static class MetadataQueryEngine
//{
//    public static IReadOnlyList<T> Apply<T>(IReadOnlyList<T> fields, CallRecordsMetadataQuery q)
//    {
//        IEnumerable<T> query = fields;

//        // 1) Field selection: ?fields=a,b,c
//        if (!string.IsNullOrWhiteSpace(q.Fields))
//        {
//            var selected = q.Fields
//                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
//                .ToHashSet(StringComparer.OrdinalIgnoreCase);

//            query = query.Where(f =>
//            {
//                var name = GetString(f!, "Name") ?? GetString(f!, "Field") ?? GetString(f!, "Key");
//                return name is not null && selected.Contains(name);
//            });
//        }

//        // 2) Filter: mini rules
//        if (!string.IsNullOrWhiteSpace(q.Filter))
//        {
//            query = ApplyFilter(query, q.Filter!);
//        }

//        // 3) Sort
//        if (!string.IsNullOrWhiteSpace(q.Sort))
//        {
//            var key = q.Sort.Trim().ToLowerInvariant();
//            var desc = string.Equals(q.SortDir, "desc", StringComparison.OrdinalIgnoreCase);

//            query = key switch
//            {
//                "name" => OrderBy(query, f => GetString(f!, "Name") ?? "", desc),
//                "classification" => OrderBy(query, f => GetString(f!, "Classification") ?? "", desc),
//                _ => query
//            };
//        }

//        return query.ToList();
//    }

//    private static IEnumerable<T> ApplyFilter<T>(IEnumerable<T> fields, string filter)
//    {
//        var f = filter.Trim();

//        var contains = TryParseContains(f);
//        if (contains is not null)
//        {
//            var (field, value) = contains.Value;
//            if (field.Equals("name", StringComparison.OrdinalIgnoreCase))
//            {
//                return fields.Where(x =>
//                {
//                    var name = GetString(x!, "Name");
//                    return name is not null && name.Contains(value, StringComparison.OrdinalIgnoreCase);
//                });
//            }
//            return fields;
//        }

//        var eq = TryParseEq(f);
//        if (eq is not null)
//        {
//            var (field, valueRaw) = eq.Value;

//            if (field.Equals("masked", StringComparison.OrdinalIgnoreCase))
//            {
//                var v = ParseBool(valueRaw);
//                if (v is null) return fields;

//                return fields.Where(x =>
//                {
//                    var b = GetBool(x!, "IsMasked") ?? GetBool(x!, "Masked");
//                    return b is not null && b.Value == v.Value;
//                });
//            }

//            if (field.Equals("pii", StringComparison.OrdinalIgnoreCase))
//            {
//                var v = ParseBool(valueRaw);
//                if (v is null) return fields;

//                return fields.Where(x =>
//                {
//                    var b = GetBool(x!, "IsPii") ?? GetBool(x!, "Pii");
//                    return b is not null && b.Value == v.Value;
//                });
//            }

//            if (field.Equals("classification", StringComparison.OrdinalIgnoreCase))
//            {
//                var v = Unquote(valueRaw);
//                return fields.Where(x =>
//                {
//                    var c = GetString(x!, "Classification");
//                    return c is not null && c.Equals(v, StringComparison.OrdinalIgnoreCase);
//                });
//            }

//            if (field.Equals("name", StringComparison.OrdinalIgnoreCase))
//            {
//                var v = Unquote(valueRaw);
//                return fields.Where(x =>
//                {
//                    var n = GetString(x!, "Name");
//                    return n is not null && n.Equals(v, StringComparison.OrdinalIgnoreCase);
//                });
//            }

//            return fields;
//        }

//        return fields;
//    }

//    private static (string field, string value)? TryParseEq(string s)
//    {
//        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
//        if (parts.Length >= 3 && parts[1].Equals("eq", StringComparison.OrdinalIgnoreCase))
//        {
//            var field = parts[0];
//            var value = string.Join(' ', parts.Skip(2));
//            return (field, value);
//        }
//        return null;
//    }

//    private static (string field, string value)? TryParseContains(string s)
//    {
//        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
//        if (parts.Length >= 3 && parts[1].Equals("contains", StringComparison.OrdinalIgnoreCase))
//        {
//            var field = parts[0];
//            var value = Unquote(string.Join(' ', parts.Skip(2)));
//            return (field, value);
//        }
//        return null;
//    }

//    private static bool? ParseBool(string raw)
//    {
//        var v = Unquote(raw).Trim();
//        if (bool.TryParse(v, out var b)) return b;
//        if (v == "1") return true;
//        if (v == "0") return false;
//        return null;
//    }

//    private static string Unquote(string raw)
//    {
//        var v = raw.Trim();
//        if (v.Length >= 2 && v.StartsWith("'") && v.EndsWith("'"))
//            return v[1..^1];
//        if (v.Length >= 2 && v.StartsWith("\"") && v.EndsWith("\""))
//            return v[1..^1];
//        return v;
//    }

//    private static IEnumerable<T> OrderBy<T>(IEnumerable<T> src, Func<T, string> key, bool desc)
//        => desc ? src.OrderByDescending(key) : src.OrderBy(key);

//    private static string? GetString<T>(T obj, string prop)
//        => obj!.GetType().GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase)
//              ?.GetValue(obj) as string;

//    private static bool? GetBool<T>(T obj, string prop)
//    {
//        if (obj == null) return null;

//        var pi = obj.GetType().GetProperty(
//            prop,
//            BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);

//        if (pi == null) return null;

//        var val = pi.GetValue(obj, null);
//        if (val == null) return null;

//        if (val is bool)
//            return (bool)val;

//        // Algunas libs/modelos exponen bool? y lo devuelven como Nullable<bool>
//        var type = val.GetType();
//        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Nullable<>))
//        {
//            var underlying = Nullable.GetUnderlyingType(type);
//            if (underlying == typeof(bool))
//            {
//                // val es Nullable<bool> boxed: si HasValue=false, val sería null (ya lo manejamos arriba)
//                return (bool)val;
//            }
//        }

//        // Si viene como string "true"/"false" (raro, pero pasa en metadata dinámica)
//        if (val is string)
//        {
//            bool parsed;
//            if (bool.TryParse((string)val, out parsed))
//                return parsed;
//        }

//        return null;
//    }

//    //Validate
//    //private static bool? GetBool<T>(T obj, string prop)
//    //{
//    //    var pi = obj!.GetType().GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
//    //    if (pi is null) return null;

//    //    var val = pi.GetValue(obj);
//    //    return val switch
//    //    {
//    //        bool b => b,
//    //        bool? bn => bn,
//    //        _ => null
//    //    };
//    //}
//}


////internal static class MetadataQueryEngine
////{
////    public static IReadOnlyList<object> Apply(IReadOnlyList<object> fields, CallRecordsMetadataQuery q)
////    {
////        IEnumerable<object> query = fields;

////        // 1) Field selection: ?fields=a,b,c
////        if (!string.IsNullOrWhiteSpace(q.Fields))
////        {
////            var selected = q.Fields
////                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
////                .ToHashSet(StringComparer.OrdinalIgnoreCase);

////            query = query.Where(f =>
////            {
////                var name = GetString(f, "Name") ?? GetString(f, "Field") ?? GetString(f, "Key");
////                return name is not null && selected.Contains(name);
////            });
////        }

////        // 2) Filter: mini rules
////        if (!string.IsNullOrWhiteSpace(q.Filter))
////        {
////            query = ApplyFilter(query, q.Filter!);
////        }

////        // 3) Sort: ?sort=name&sortDir=asc
////        if (!string.IsNullOrWhiteSpace(q.Sort))
////        {
////            var key = q.Sort.Trim().ToLowerInvariant();
////            var desc = string.Equals(q.SortDir, "desc", StringComparison.OrdinalIgnoreCase);

////            query = key switch
////            {
////                "name" => OrderBy(query, f => GetString(f, "Name") ?? "", desc),
////                "classification" => OrderBy(query, f => GetString(f, "Classification") ?? "", desc),
////                _ => query
////            };
////        }

////        return query.ToList();
////    }

////    private static IEnumerable<object> ApplyFilter(IEnumerable<object> fields, string filter)
////    {
////        var f = filter.Trim();

////        // Supported:
////        //  - masked eq true/false
////        //  - pii eq true/false
////        //  - classification eq 'Internal'
////        //  - name eq 'timestamp'
////        //  - name contains 'user'
////        //
////        // Reglas: si no matchea, no filtra (para no romper UX)
////        // Puedes cambiar esto a "throw" si prefieres strict mode.

////        // name contains 'x'
////        var contains = TryParseContains(f);
////        if (contains is not null)
////        {
////            var (field, value) = contains.Value;
////            if (field.Equals("name", StringComparison.OrdinalIgnoreCase))
////            {
////                return fields.Where(x =>
////                {
////                    var name = GetString(x, "Name");
////                    return name is not null && name.Contains(value, StringComparison.OrdinalIgnoreCase);
////                });
////            }
////            return fields;
////        }

////        // field eq value
////        var eq = TryParseEq(f);
////        if (eq is not null)
////        {
////            var (field, valueRaw) = eq.Value;

////            if (field.Equals("masked", StringComparison.OrdinalIgnoreCase))
////            {
////                var v = ParseBool(valueRaw);
////                if (v is null) return fields;

////                return fields.Where(x =>
////                {
////                    // soporta IsMasked o Masked
////                    var b = GetBool(x, "IsMasked") ?? GetBool(x, "Masked");
////                    return b is not null && b.Value == v.Value;
////                });
////            }

////            if (field.Equals("pii", StringComparison.OrdinalIgnoreCase))
////            {
////                var v = ParseBool(valueRaw);
////                if (v is null) return fields;

////                return fields.Where(x =>
////                {
////                    var b = GetBool(x, "IsPii") ?? GetBool(x, "Pii");
////                    return b is not null && b.Value == v.Value;
////                });
////            }

////            if (field.Equals("classification", StringComparison.OrdinalIgnoreCase))
////            {
////                var v = Unquote(valueRaw);
////                return fields.Where(x =>
////                {
////                    var c = GetString(x, "Classification");
////                    return c is not null && c.Equals(v, StringComparison.OrdinalIgnoreCase);
////                });
////            }

////            if (field.Equals("name", StringComparison.OrdinalIgnoreCase))
////            {
////                var v = Unquote(valueRaw);
////                return fields.Where(x =>
////                {
////                    var n = GetString(x, "Name");
////                    return n is not null && n.Equals(v, StringComparison.OrdinalIgnoreCase);
////                });
////            }

////            return fields;
////        }

////        return fields;
////    }

////    private static (string field, string value)? TryParseEq(string s)
////    {
////        // field eq value
////        // e.g. masked eq true, classification eq 'Internal'
////        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
////        if (parts.Length >= 3 && parts[1].Equals("eq", StringComparison.OrdinalIgnoreCase))
////        {
////            var field = parts[0];
////            var value = string.Join(' ', parts.Skip(2));
////            return (field, value);
////        }
////        return null;
////    }

////    private static (string field, string value)? TryParseContains(string s)
////    {
////        // name contains 'user'
////        var parts = s.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
////        if (parts.Length >= 3 && parts[1].Equals("contains", StringComparison.OrdinalIgnoreCase))
////        {
////            var field = parts[0];
////            var value = Unquote(string.Join(' ', parts.Skip(2)));
////            return (field, value);
////        }
////        return null;
////    }

////    private static bool? ParseBool(string raw)
////    {
////        var v = Unquote(raw).Trim();
////        if (bool.TryParse(v, out var b)) return b;
////        if (v == "1") return true;
////        if (v == "0") return false;
////        return null;
////    }

////    private static string Unquote(string raw)
////    {
////        var v = raw.Trim();
////        if (v.Length >= 2 && v.StartsWith("'") && v.EndsWith("'"))
////            return v[1..^1];
////        if (v.Length >= 2 && v.StartsWith("\"") && v.EndsWith("\""))
////            return v[1..^1];
////        return v;
////    }

////    private static IEnumerable<object> OrderBy(IEnumerable<object> src, Func<object, string> key, bool desc)
////        => desc ? src.OrderByDescending(key) : src.OrderBy(key);

////    private static string? GetString(object obj, string prop)
////        => obj.GetType().GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase)
////              ?.GetValue(obj) as string;

////    private static bool? GetBool(object obj, string prop)
////    {
////        var pi = obj.GetType().GetProperty(prop, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
////        if (pi is null) return null;

////        var val = pi.GetValue(obj);
////        return val switch
////        {
////            bool b => b,
////            bool? bn => bn,
////            _ => null
////        };
////    }
////}
