<#
.SYNOPSIS
Builds the admin consent URL for a multi-tenant app.

USAGE
  pwsh ./Admin-Consent-Url.ps1 -CustomerTenantId "<TENANT_B_ID>" -ClientId "<API_CLIENT_ID>" -RedirectUri "https://localhost:7249/auth/consent-callback"
#>

param(
  [Parameter(Mandatory=$true)][string]$CustomerTenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$RedirectUri
)

$redirect = [System.Web.HttpUtility]::UrlEncode($RedirectUri)
"https://login.microsoftonline.com/$CustomerTenantId/adminconsent?client_id=$ClientId&redirect_uri=$redirect"
