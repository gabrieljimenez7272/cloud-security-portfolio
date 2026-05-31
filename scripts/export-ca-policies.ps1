<#
.SYNOPSIS
    Exports all Conditional Access policies to JSON files for version control.
.REQUIREMENTS
    Connect-MgGraph -Scopes "Policy.Read.All"
#>

#Requires -Modules Microsoft.Graph.Identity.SignIns

$OutputDir = Join-Path $PSScriptRoot "../m365/conditional-access/policies/exported"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$Policies = Get-MgIdentityConditionalAccessPolicy -All

foreach ($Policy in $Policies) {
    $SafeName = $Policy.DisplayName -replace '[^a-zA-Z0-9-_]', '_'
    $FilePath = Join-Path $OutputDir "$SafeName.json"
    $Policy | ConvertTo-Json -Depth 20 | Out-File $FilePath -Encoding UTF8
    Write-Host "Exported: $($Policy.DisplayName)" -ForegroundColor Green
}

Write-Host "`nExported $($Policies.Count) policies to $OutputDir" -ForegroundColor Cyan
