<#
.SYNOPSIS
Builds the admin consent URL for a multi-tenant app.

USAGE
  pwsh ./Admin-Consent-Url.ps1 -CustomerTenantId "068733c0-9d09-4079-aa1f-c80a67664994" -ClientId "58a207b2-e309-4156-914f-87618b42c8b5" -RedirectUri "https://localhost:7249/auth/consent-callback"
#>

param(
  [Parameter(Mandatory=$true)][string]$CustomerTenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$RedirectUri
)

$redirect = [System.Web.HttpUtility]::UrlEncode($RedirectUri)
"https://login.microsoftonline.com/$CustomerTenantId/adminconsent?client_id=$ClientId&redirect_uri=$redirect"
