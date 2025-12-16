<#
.SYNOPSIS
Creates a Service Principal in a target tenant for an existing multi-tenant App Registration.

USAGE
  pwsh ./Register-ServicePrincipal.ps1 -TenantId "<TENANT_ID>" -AppId "<API_CLIENT_ID>"

REQUIRES
  - Microsoft.Graph PowerShell modules
  - Directory permissions to create service principals (usually a tenant admin)

#>

param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$AppId
)

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force | Out-Null

$module = "Microsoft.Graph.Applications"
if ($null -eq (Get-Module -ListAvailable -Name $module)) {
  Install-Module $module -Scope CurrentUser -Force
}

Connect-MgGraph -TenantId $TenantId -Scopes "Application.ReadWrite.All"

$params = @{
  appId = $AppId
}

New-MgServicePrincipal -BodyParameter $params | Format-List Id,AppId,DisplayName
