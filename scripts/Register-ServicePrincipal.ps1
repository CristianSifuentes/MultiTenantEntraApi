<#
.SYNOPSIS
Creates a Service Principal in a target tenant for an existing multi-tenant App Registration.
mi correo personal->
USAGE
  pwsh ./Register-ServicePrincipal.ps1 -TenantId "51abcaf2-43cc-48f6-9356-dbd3236ba843" -AppId "58a207b2-e309-4156-914f-87618b42c8b5"

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
