<#
.SYNOPSIS
    Deploys Conditional Access policies from JSON files in the policies/ directory.
.REQUIREMENTS
    Microsoft.Graph PowerShell module
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"
#>

#Requires -Modules Microsoft.Graph.Identity.SignIns

$PoliciesPath = Join-Path $PSScriptRoot "../policies"
$PolicyFiles  = Get-ChildItem -Path $PoliciesPath -Filter "*.json"

foreach ($File in $PolicyFiles) {
    $PolicyBody = Get-Content $File.FullName -Raw | ConvertFrom-Json -Depth 20

    $Existing = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$($PolicyBody.displayName)'"

    if ($Existing) {
        Write-Host "Updating: $($PolicyBody.displayName)" -ForegroundColor Cyan
        Update-MgIdentityConditionalAccessPolicy `
            -ConditionalAccessPolicyId $Existing.Id `
            -BodyParameter ($PolicyBody | ConvertTo-Json -Depth 20)
    } else {
        Write-Host "Creating: $($PolicyBody.displayName)" -ForegroundColor Green
        New-MgIdentityConditionalAccessPolicy -BodyParameter ($PolicyBody | ConvertTo-Json -Depth 20)
    }
}

Write-Host "Done." -ForegroundColor Green
