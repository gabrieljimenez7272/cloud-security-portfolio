<#
.SYNOPSIS
    Retrieves active Microsoft Defender XDR alerts filtered by severity and status.
    Outputs a summary table and optionally exports to CSV.

.PARAMETER Severity
    Filter by severity: High, Medium, Low, Informational (default: High,Medium)

.PARAMETER Status
    Filter by status: New, InProgress, Resolved (default: New,InProgress)

.PARAMETER ExportCsv
    If specified, exports results to this file path.

.REQUIREMENTS
    Connect-MgGraph -Scopes "SecurityAlert.Read.All"

.EXAMPLE
    .\Get-DefenderAlerts.ps1 -Severity High -ExportCsv ./alerts.csv
#>

#Requires -Modules Microsoft.Graph.Security

[CmdletBinding()]
param(
    [string[]]$Severity   = @("High", "Medium"),
    [string[]]$Status     = @("New", "InProgress"),
    [string]  $ExportCsv  = ""
)

$Filter = "severity in ('$($Severity -join "','")') and status in ('$($Status -join "','")')"

Write-Host "Fetching Defender alerts..." -ForegroundColor Cyan
$Alerts = Get-MgSecurityAlert_v2 -Filter $Filter -All

if (-not $Alerts) {
    Write-Host "No alerts found matching criteria." -ForegroundColor Green
    return
}

$Report = $Alerts | Select-Object `
    @{N="AlertId";         E={$_.Id}},
    @{N="Title";           E={$_.Title}},
    @{N="Severity";        E={$_.Severity}},
    @{N="Status";          E={$_.Status}},
    @{N="Category";        E={$_.Category}},
    @{N="CreatedDateTime"; E={$_.CreatedDateTime}},
    @{N="AssignedTo";      E={$_.AssignedTo}},
    @{N="ProductName";     E={$_.VendorInformation.SubProvider}}

Write-Host "`nActive Alerts ($($Alerts.Count) total):" -ForegroundColor Yellow
$Report | Sort-Object Severity, CreatedDateTime | Format-Table -AutoSize

$HighCount = ($Alerts | Where-Object { $_.Severity -eq "High" }).Count
$MedCount  = ($Alerts | Where-Object { $_.Severity -eq "Medium" }).Count
Write-Host "Summary: $HighCount High  |  $MedCount Medium" -ForegroundColor Cyan

if ($ExportCsv) {
    $Report | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to: $ExportCsv" -ForegroundColor Green
}
