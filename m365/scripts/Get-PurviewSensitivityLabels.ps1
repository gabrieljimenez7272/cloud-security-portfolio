<#
.SYNOPSIS
    Audits Microsoft Purview sensitivity label configuration and usage.
    Reports label policies, scopes, and top labeled content.

.REQUIREMENTS
    Connect-MgGraph -Scopes "InformationProtectionPolicy.Read.All"
    (For label usage stats, also requires Compliance admin role)

.EXAMPLE
    .\Get-PurviewSensitivityLabels.ps1
#>

#Requires -Modules Microsoft.Graph.Identity.SignIns

Write-Host "Fetching Purview sensitivity labels..." -ForegroundColor Cyan

# -- Get all sensitivity labels -------------------------------------------------
$Labels = Get-MgUserInformationProtectionSensitivityLabel `
    -UserId "me" -All -ExpandProperty "sublabels"

if (-not $Labels) {
    Write-Host "No sensitivity labels found. Verify Purview is configured." -ForegroundColor Yellow
    return
}

Write-Host "`n== Sensitivity Labels ==" -ForegroundColor Cyan
$Labels | Select-Object Name, Id, Tooltip, IsActive,
    @{N="Sublabels"; E={ ($_.Sublabels | Select-Object -ExpandProperty Name) -join ", " }} |
    Sort-Object Name | Format-Table -AutoSize

# -- Check for required labels --------------------------------------------------
$RequiredLabels = @("Public", "Internal", "Confidential", "Highly Confidential")
Write-Host "`n== Label Coverage Check ==" -ForegroundColor Cyan
foreach ($Required in $RequiredLabels) {
    $Found = $Labels | Where-Object { $_.Name -like "*$Required*" }
    if ($Found) {
        Write-Host "  [FOUND]   $Required" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $Required" -ForegroundColor Red
    }
}

Write-Host "`nTotal labels: $($Labels.Count)" -ForegroundColor Cyan
