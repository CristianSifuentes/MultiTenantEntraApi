# MultiTenantEntraApi (.NET 8) — Multi-tenant API + Entra ID (2 tenants)

This repo is a **runnable** .NET 8 Minimal API that validates **Microsoft Entra ID JWTs** issued from **multiple tenants**, using a **tenant allow-list** plus **scope/app-role authorization**.

It mirrors what your slides show:

- Single-tenant vs multi-tenant apps/APIs
- User consent vs admin consent
- Service Principal creation in the customer tenant
- Expose an API (scopes) + App roles

## What you get

### Endpoints
- `GET /health` (anonymous)
- `GET /whoami` (requires any valid Entra token)
- `GET /documents` (requires delegated scope `Documents.Read`)
- `GET /reports` (requires app role `Reports.Read.All` **or** delegated scope `Reports.Read.All`)

### Security model (real-world)
- `authority: https://login.microsoftonline.com/common/v2.0`
- Custom **issuer validation** with an allow-list (`tid`-based)
- Audience (`aud`) validated as your API **Application ID URI**
- Supports:
  - Delegated scopes in `scp`
  - App roles in `roles`

## Layout

```
.
├─ src/
│  └─ MultiTenantApi/
│     ├─ Program.cs
│     ├─ Security/
│     │  ├─ TenantAllowListIssuerValidator.cs
│     │  ├─ AuthzPolicies.cs
│     │  └─ ClaimsExtensions.cs
│     ├─ appsettings.json
│     ├─ appsettings.Development.json
│     └─ MultiTenantApi.csproj
└─ scripts/
   ├─ Register-ServicePrincipal.ps1
   ├─ Admin-Consent-Url.ps1
   └─ Graph-Grant-AppRole.ps1
```

## Prereqs
- .NET SDK 8.x
- Two Entra tenants:
  - **Tenant A = Developer** (register the API)
  - **Tenant B = Customer** (consume the API)

## Run locally

```bash
cd src/MultiTenantApi
dotnet restore
dotnet run
```

Default:
- https://localhost:7249
- http://localhost:5249

---

# Tenant setup (step-by-step)

## 1) Tenant A — Register the API (Multi-tenant)

### 1.1 Create App Registration (API)
Entra → App registrations → New registration

- Name: `MultiTenantApi`
- Supported account types:
  - ✅ Accounts in any organizational directory (Any Entra tenant) **(Multitenant)**

Copy:
- **Application (client) ID** = `API_CLIENT_ID`

### 1.2 Expose the API (Application ID URI + scopes)
App → Expose an API

1) Set Application ID URI (recommended):
- `api://{API_CLIENT_ID}`

2) Add scopes:
- `Documents.Read` (Admins and users)
- `Reports.Read.All` (Admins only)

### 1.3 Add App Roles (for app-only / daemon)
App → App roles

Create:
- Display name: `Reports.Read.All`
- Allowed member types: **Application** (optionally also User)
- Value: `Reports.Read.All`

---

## 2) Tenant B — Admin consent + Service Principal provisioning

### Option A (recommended): Admin consent endpoint
Open as a **Tenant B admin**:

```text
https://login.microsoftonline.com/{TENANT_B_ID}/adminconsent?client_id={API_CLIENT_ID}&redirect_uri=https://localhost:7249/auth/consent-callback
```

Result:
- Tenant B creates **Enterprise Application** (service principal) for `MultiTenantApi`

> Important: your slides mention you need `User.Read` for some admin-consent flows because the admin must authenticate first. In this sample, we keep the redirect simple and focus on the API side; you can add Microsoft Graph delegated scopes on the **client** app when needed.

---

## 3) Tenant B — Create a client app (Postman/Swagger/UI)

Create App registration: `MultiTenantApi-Client`

Add Redirect URI:
- Postman: `https://oauth.pstmn.io/v1/callback`
- Swagger: `https://localhost:7249/swagger/oauth2-redirect.html`

### Delegated permissions
Client app → API permissions → My APIs → `MultiTenantApi` → add:
- `Documents.Read`

Grant consent if needed.

---

## 4) Configure appsettings
Edit `src/MultiTenantApi/appsettings.Development.json`:

- `AzureAd.ClientId` = `{API_CLIENT_ID}` (Tenant A)
- `AzureAd.Audience` = `api://{API_CLIENT_ID}`
- `Tenancy.AllowedTenants` add `{TENANT_B_ID}` (and optionally Tenant A)

---

## 5) Test calls

### Delegated (Authorization Code)
Scope:
- `api://{API_CLIENT_ID}/Documents.Read`

Call:
- `GET https://localhost:7249/documents` with `Authorization: Bearer <token>`

### App-only (client_credentials)
- Grant app role `Reports.Read.All` to your client service principal (script included)
- Call:
  - `GET https://localhost:7249/reports`

---

## Production notes
- Keep the allow-list ON
- Prefer certificates for daemon apps
- Log `tid`, `oid`, `azp/appid`, `scp`, `roles` for auditability
