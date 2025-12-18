<#
.SYNOPSIS
Grant an App Role (application permission) from a resource Service Principal to a client Service Principal.

This is how you enable client_credentials access to your API by app roles.

High level:
  1) Resource = your API (service principal in customer tenant)
  2) Client   = the daemon/client app's service principal (in customer tenant)
  3) Assign resource appRole -> client

USAGE
  pwsh ./Graph-Grant-AppRole.ps1 -TenantId "068733c0-9d09-4079-aa1f-c80a67664994" -ResourceAppId "58a207b2-e309-4156-914f-87618b42c8b5" -ClientAppId "7c3f9357-5ac1-4a54-bfb9-802d8219684d" -AppRoleValue "Reports.Read.All"

REQUIRES
  Microsoft.Graph modules and permissions:
    AppRoleAssignment.ReadWrite.All
#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ResourceAppId,
  [Parameter(Mandatory=$true)][string]$ClientAppId,
  [Parameter(Mandatory=$true)][string]$AppRoleValue
)

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force | Out-Null

$module = "Microsoft.Graph.Applications"
if ($null -eq (Get-Module -ListAvailable -Name $module)) {
  Install-Module $module -Scope CurrentUser -Force
}

Connect-MgGraph -TenantId $TenantId -Scopes "AppRoleAssignment.ReadWrite.All","Application.Read.All"

# Resolve service principals
$resourceSp = Get-MgServicePrincipal -Filter "appId eq '$ResourceAppId'" -ConsistencyLevel eventual -CountVariable count
if (-not $resourceSp) { throw "Resource Service Principal not found for appId=$ResourceAppId" }

$clientSp = Get-MgServicePrincipal -Filter "appId eq '$ClientAppId'" -ConsistencyLevel eventual -CountVariable count
if (-not $clientSp) { throw "Client Service Principal not found for appId=$ClientAppId" }

# Find the app role on the resource
$appRole = $resourceSp.AppRoles | Where-Object { $_.Value -eq $AppRoleValue -and $_.IsEnabled -eq $true }
if (-not $appRole) { throw "App role '$AppRoleValue' not found or not enabled on resource." }

$body = @{
  principalId = $clientSp.Id
  resourceId  = $resourceSp.Id
  appRoleId   = $appRole.Id
}

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $clientSp.Id -BodyParameter $body | Format-List
