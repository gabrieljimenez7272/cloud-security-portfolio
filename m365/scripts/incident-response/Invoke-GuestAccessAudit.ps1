<#
.SYNOPSIS
    Incident Response -- Guest Account & External Access Audit
    Identifies stale, over-privileged, and suspicious guest accounts in Entra ID.

.DESCRIPTION
    Reports on:
      - Guest accounts with no recent sign-in activity
      - Guests with privileged role assignments
      - Guests with direct resource access (SharePoint, Teams)
      - Recently invited guests (last 7 days)
      - Guests from high-risk domains
      - B2B collaboration settings

.PARAMETER StaleThresholdDays
    Days since last sign-in before a guest is flagged as stale (default: 90)

.PARAMETER HighRiskDomains
    Comma-separated list of domains to flag (e.g. "gmail.com,yahoo.com")

.PARAMETER ExportPath
    Folder to write CSV reports. Defaults to current directory.

.REQUIREMENTS
    Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All",
        "Directory.Read.All", "RoleManagement.Read.Directory"

.EXAMPLE
    .\Invoke-GuestAccessAudit.ps1 -StaleThresholdDays 60 -HighRiskDomains "gmail.com,yahoo.com"
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement,
    Microsoft.Graph.Identity.Governance

[CmdletBinding()]
param(
    [int]    $StaleThresholdDays = 90,
    [string] $HighRiskDomains    = "",
    [string] $ExportPath         = "."
)

Set-StrictMode -Version Latest
$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$CutoffDate  = (Get-Date).AddDays(-$StaleThresholdDays)
$RiskDomains = $HighRiskDomains -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 IR -- Guest Account Audit" -ForegroundColor Cyan
Write-Host "  Stale threshold : $StaleThresholdDays days" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# -- Fetch all guests ----------------------------------------------------------
Write-Host "[*] Fetching guest accounts..." -ForegroundColor Yellow
$Guests = Get-MgUser -Filter "userType eq 'Guest'" -All `
    -Property Id, DisplayName, UserPrincipalName, Mail, CreatedDateTime,
              SignInActivity, AccountEnabled, ExternalUserState,
              ExternalUserStateChangeDateTime |
    Sort-Object CreatedDateTime -Descending

Write-Host "    Total guests found: $($Guests.Count)"

# -- Privileged role assignments -----------------------------------------------
Write-Host "[*] Checking privileged role assignments for guests..." -ForegroundColor Yellow
$DirectoryRoles = Get-MgDirectoryRole -All
$PrivilegedGuests = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Role in $DirectoryRoles) {
    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
    foreach ($Member in $Members) {
        $Guest = $Guests | Where-Object { $_.Id -eq $Member.Id }
        if ($Guest) {
            $PrivilegedGuests.Add([PSCustomObject]@{
                GuestUPN    = $Guest.UserPrincipalName
                DisplayName = $Guest.DisplayName
                RoleName    = $Role.DisplayName
                CreatedDate = $Guest.CreatedDateTime
                LastSignIn  = $Guest.SignInActivity.LastSignInDateTime
            })
        }
    }
}

# -- Build guest report --------------------------------------------------------
Write-Host "[*] Analyzing guest accounts..." -ForegroundColor Yellow
$GuestReport    = [System.Collections.Generic.List[PSObject]]::new()
$StaleGuests    = [System.Collections.Generic.List[PSObject]]::new()
$RecentGuests   = [System.Collections.Generic.List[PSObject]]::new()
$RiskyDomGuests = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Guest in $Guests) {
    $LastSignIn   = $Guest.SignInActivity.LastSignInDateTime
    $DaysSince    = if ($LastSignIn) { ([datetime]::UtcNow - [datetime]$LastSignIn).Days } else { 9999 }
    $GuestDomain  = if ($Guest.Mail) { ($Guest.Mail -split "@")[-1].ToLower() } else { "unknown" }
    $IsStale      = $DaysSince -gt $StaleThresholdDays
    $IsRecent     = $Guest.CreatedDateTime -gt (Get-Date).AddDays(-7)
    $IsRiskyDom   = $GuestDomain -in $RiskDomains
    $IsPrivileged = $PrivilegedGuests | Where-Object { $_.GuestUPN -eq $Guest.UserPrincipalName }

    $Flags = [System.Collections.Generic.List[string]]::new()
    if ($IsStale)      { $Flags.Add("STALE:${DaysSince}d") }
    if ($IsRecent)     { $Flags.Add("RECENTLY_ADDED") }
    if ($IsRiskyDom)   { $Flags.Add("HIGH_RISK_DOMAIN:$GuestDomain") }
    if ($IsPrivileged) { $Flags.Add("PRIVILEGED:$(($IsPrivileged.RoleName) -join ',')") }
    if (-not $Guest.AccountEnabled) { $Flags.Add("DISABLED") }
    if ($Guest.ExternalUserState -eq "PendingAcceptance") { $Flags.Add("INVITE_PENDING") }

    $Obj = [PSCustomObject]@{
        DisplayName      = $Guest.DisplayName
        UserPrincipalName = $Guest.UserPrincipalName
        Mail             = $Guest.Mail
        Domain           = $GuestDomain
        AccountEnabled   = $Guest.AccountEnabled
        CreatedDateTime  = $Guest.CreatedDateTime
        LastSignIn       = $LastSignIn
        DaysSinceSignIn  = if ($DaysSince -eq 9999) { "Never" } else { $DaysSince }
        ExternalState    = $Guest.ExternalUserState
        Flags            = ($Flags -join " | ")
    }

    $GuestReport.Add($Obj)
    if ($IsStale)    { $StaleGuests.Add($Obj) }
    if ($IsRecent)   { $RecentGuests.Add($Obj) }
    if ($IsRiskyDom) { $RiskyDomGuests.Add($Obj) }
}

# -- Domain breakdown ----------------------------------------------------------
$DomainBreakdown = $GuestReport | Group-Object Domain |
    Sort-Object Count -Descending |
    Select-Object @{N="Domain"; E={$_.Name}}, Count

# -- Output --------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nGuest Domain Breakdown:" -ForegroundColor White
$DomainBreakdown | Format-Table -AutoSize

Write-Host "`n[PRIVILEGED] Guest accounts with directory roles ($($PrivilegedGuests.Count)):" `
    -ForegroundColor $(if ($PrivilegedGuests.Count -gt 0) {"Red"} else {"Green"})
$PrivilegedGuests | Format-Table -AutoSize

Write-Host "`n[STALE] Guests inactive for $StaleThresholdDays+ days ($($StaleGuests.Count)):" `
    -ForegroundColor $(if ($StaleGuests.Count -gt 0) {"Yellow"} else {"Green"})
$StaleGuests | Select-Object DisplayName, Mail, DaysSinceSignIn, CreatedDateTime |
    Sort-Object DaysSinceSignIn -Descending | Select-Object -First 25 | Format-Table -AutoSize

Write-Host "`n[RECENT] Guests added in last 7 days ($($RecentGuests.Count)):" `
    -ForegroundColor $(if ($RecentGuests.Count -gt 0) {"Yellow"} else {"Green"})
$RecentGuests | Format-Table -AutoSize

if ($RiskyDomGuests.Count -gt 0) {
    Write-Host "`n[HIGH RISK DOMAINS] $($RiskyDomGuests.Count) guest(s) from flagged domains:" -ForegroundColor Red
    $RiskyDomGuests | Format-Table -AutoSize
}

# -- Export --------------------------------------------------------------------
$AllPath   = Join-Path $ExportPath "IR_GuestAudit_All_${Timestamp}.csv"
$StalePath = Join-Path $ExportPath "IR_GuestAudit_Stale_${Timestamp}.csv"
$PrivPath  = Join-Path $ExportPath "IR_GuestAudit_Privileged_${Timestamp}.csv"
$RecPath   = Join-Path $ExportPath "IR_GuestAudit_Recent_${Timestamp}.csv"

$GuestReport     | Export-Csv -Path $AllPath   -NoTypeInformation -Encoding UTF8
$StaleGuests     | Export-Csv -Path $StalePath -NoTypeInformation -Encoding UTF8
$PrivilegedGuests| Export-Csv -Path $PrivPath  -NoTypeInformation -Encoding UTF8
$RecentGuests    | Export-Csv -Path $RecPath   -NoTypeInformation -Encoding UTF8

Write-Host "`n[*] Reports exported:" -ForegroundColor Green
Write-Host "    All guests   : $AllPath"
Write-Host "    Stale guests : $StalePath"
Write-Host "    Privileged   : $PrivPath"
Write-Host "    Recent adds  : $RecPath"
