<#
.SYNOPSIS
    Retrieves active Microsoft Defender for Cloud security alerts across subscriptions.

.PARAMETER SubscriptionIds
    One or more Azure subscription IDs. If omitted, runs against all accessible subscriptions.

.PARAMETER MinSeverity
    Minimum severity to include: High, Medium, Low (default: High)

.REQUIREMENTS
    az login  (or Connect-AzAccount)
    Az.Security module

.EXAMPLE
    .\Get-DefenderForCloudAlerts.ps1 -MinSeverity Medium
#>

#Requires -Modules Az.Security, Az.Accounts

[CmdletBinding()]
param(
    [string[]]$SubscriptionIds = @(),
    [ValidateSet("High","Medium","Low")]
    [string]  $MinSeverity = "High"
)

$SeverityRank = @{ High = 3; Medium = 2; Low = 1 }
$MinRank      = $SeverityRank[$MinSeverity]

if ($SubscriptionIds.Count -eq 0) {
    $SubscriptionIds = (Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }).Id
    Write-Host "Scanning $($SubscriptionIds.Count) subscription(s)..." -ForegroundColor Cyan
}

$AllAlerts = @()

foreach ($SubId in $SubscriptionIds) {
    Set-AzContext -SubscriptionId $SubId -ErrorAction SilentlyContinue | Out-Null
    $Alerts = Get-AzSecurityAlert | Where-Object {
        $SeverityRank[$_.Severity] -ge $MinRank -and $_.Status -ne "Dismissed"
    }
    $AllAlerts += $Alerts | Select-Object `
        @{N="Subscription"; E={$SubId}},
        AlertDisplayName, Severity, Status,
        CompromisedEntity, AlertType,
        @{N="TimeGenerated"; E={$_.TimeGeneratedUtc}}
}

if (-not $AllAlerts) {
    Write-Host "No active alerts at $MinSeverity+ severity." -ForegroundColor Green
    return
}

Write-Host "`nDefender for Cloud Alerts ($($AllAlerts.Count) total >= $MinSeverity):" -ForegroundColor Yellow
$AllAlerts | Sort-Object Severity, TimeGenerated | Format-Table -AutoSize
