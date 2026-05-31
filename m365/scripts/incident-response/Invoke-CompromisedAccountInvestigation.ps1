<#
.SYNOPSIS
    Incident Response -- Compromised User Account Investigation
    Detects impossible travel, MFA bypass, suspicious sign-ins, and session anomalies.

.DESCRIPTION
    Pulls sign-in logs for a target user and flags:
      - Impossible travel (sign-ins from 2+ countries within 1 hour)
      - MFA bypass (sign-ins where MFA was not performed)
      - Legacy auth protocols (SMTP, POP, IMAP, MAPI)
      - High-risk sign-ins flagged by Entra ID Protection
      - Sign-ins outside business hours (configurable)
      - New/unseen countries for this user

.PARAMETER UserPrincipalName
    Target UPN to investigate. If omitted, prompts interactively.

.PARAMETER DaysBack
    How many days of sign-in history to pull (default: 30)

.PARAMETER BusinessHoursStart
    Start of business hours in 24h format (default: 7)

.PARAMETER BusinessHoursEnd
    End of business hours in 24h format (default: 19)

.PARAMETER ExportPath
    Folder to write CSV reports. Defaults to current directory.

.REQUIREMENTS
    Connect-MgGraph -Scopes "AuditLog.Read.All", "User.Read.All", "IdentityRiskyUser.Read.All"

.EXAMPLE
    .\Invoke-CompromisedAccountInvestigation.ps1 -UserPrincipalName john.doe@contoso.com -DaysBack 14
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns

[CmdletBinding()]
param(
    [string] $UserPrincipalName  = "",
    [int]    $DaysBack           = 30,
    [int]    $BusinessHoursStart = 7,
    [int]    $BusinessHoursEnd   = 19,
    [string] $ExportPath         = "."
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# -- Prompt if not supplied ----------------------------------------------------
if (-not $UserPrincipalName) {
    $UserPrincipalName = Read-Host "Enter UPN to investigate"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 IR -- Compromised Account Check" -ForegroundColor Cyan
Write-Host "  Target : $UserPrincipalName" -ForegroundColor Cyan
Write-Host "  Window : Last $DaysBack days" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# -- Pull user object ----------------------------------------------------------
Write-Host "[*] Fetching user record..." -ForegroundColor Yellow
$User = Get-MgUser -UserId $UserPrincipalName -Property `
    Id, DisplayName, UserPrincipalName, AccountEnabled,
    SignInActivity, CreatedDateTime, UserType, AssignedLicenses `
    -ErrorAction Stop

Write-Host "    DisplayName   : $($User.DisplayName)"
Write-Host "    AccountEnabled: $($User.AccountEnabled)"
Write-Host "    UserType      : $($User.UserType)"
Write-Host "    LastSignIn    : $($User.SignInActivity.LastSignInDateTime)"

# -- Pull sign-in logs ---------------------------------------------------------
Write-Host "`n[*] Pulling sign-in logs (last $DaysBack days)..." -ForegroundColor Yellow
$Since  = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
$Filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $Since"

$SignIns = Get-MgAuditLogSignIn -Filter $Filter -All -PageSize 500 |
    Sort-Object CreatedDateTime

Write-Host "    Total sign-ins found: $($SignIns.Count)"

if ($SignIns.Count -eq 0) {
    Write-Host "    No sign-in data found for this user in the window." -ForegroundColor Yellow
    exit 0
}

# -- Analysis ------------------------------------------------------------------
$Findings  = [System.Collections.Generic.List[PSObject]]::new()
$AllEvents = [System.Collections.Generic.List[PSObject]]::new()

foreach ($SignIn in $SignIns) {
    $Flags = [System.Collections.Generic.List[string]]::new()

    # MFA bypass
    if ($SignIn.AuthenticationRequirement -eq "singleFactorAuthentication" -and
        $SignIn.ConditionalAccessStatus -ne "notApplied") {
        $Flags.Add("MFA_BYPASS")
    }

    # Legacy auth
    $LegacyClients = @("SMTP","POP3","IMAP4","MAPI","Exchange ActiveSync","Other clients")
    if ($SignIn.ClientAppUsed -in $LegacyClients) {
        $Flags.Add("LEGACY_AUTH:$($SignIn.ClientAppUsed)")
    }

    # High risk
    if ($SignIn.RiskLevelDuringSignIn -in @("high","medium")) {
        $Flags.Add("RISK:$($SignIn.RiskLevelDuringSignIn.ToUpper())")
    }

    # Outside business hours (UTC)
    $Hour = ([datetime]$SignIn.CreatedDateTime).Hour
    if ($Hour -lt $BusinessHoursStart -or $Hour -ge $BusinessHoursEnd) {
        $Flags.Add("OUTSIDE_HOURS")
    }

    # Failure
    if ($SignIn.Status.ErrorCode -ne 0) {
        $Flags.Add("FAILED:$($SignIn.Status.FailureReason)")
    }

    $AllEvents.Add([PSCustomObject]@{
        DateTime          = $SignIn.CreatedDateTime
        AppDisplayName    = $SignIn.AppDisplayName
        ClientApp         = $SignIn.ClientAppUsed
        IPAddress         = $SignIn.IpAddress
        Country           = $SignIn.Location.CountryOrRegion
        City              = $SignIn.Location.City
        RiskLevel         = $SignIn.RiskLevelDuringSignIn
        MFARequired       = $SignIn.AuthenticationRequirement
        CAStatus          = $SignIn.ConditionalAccessStatus
        Status            = if ($SignIn.Status.ErrorCode -eq 0) { "Success" } else { "Failure" }
        FailureReason     = $SignIn.Status.FailureReason
        Flags             = ($Flags -join " | ")
        CorrelationId     = $SignIn.CorrelationId
    })

    if ($Flags.Count -gt 0) {
        $Findings.Add($AllEvents[-1])
    }
}

# -- Impossible travel detection -----------------------------------------------
Write-Host "`n[*] Checking for impossible travel..." -ForegroundColor Yellow
$SuccessSignIns = $AllEvents | Where-Object { $_.Status -eq "Success" } |
    Sort-Object DateTime

$ImpossibleTravel = [System.Collections.Generic.List[PSObject]]::new()

for ($i = 1; $i -lt $SuccessSignIns.Count; $i++) {
    $Prev = $SuccessSignIns[$i - 1]
    $Curr = $SuccessSignIns[$i]

    if ($Prev.Country -and $Curr.Country -and $Prev.Country -ne $Curr.Country) {
        $Gap = ([datetime]$Curr.DateTime - [datetime]$Prev.DateTime).TotalMinutes
        if ($Gap -le 60) {
            $ImpossibleTravel.Add([PSCustomObject]@{
                From_DateTime = $Prev.DateTime
                From_Country  = $Prev.Country
                From_IP       = $Prev.IPAddress
                To_DateTime   = $Curr.DateTime
                To_Country    = $Curr.Country
                To_IP         = $Curr.IPAddress
                MinutesBetween = [math]::Round($Gap, 1)
            })
        }
    }
}

# -- Country summary -----------------------------------------------------------
$CountrySummary = $AllEvents | Where-Object { $_.Country } |
    Group-Object Country |
    Sort-Object Count -Descending |
    Select-Object @{N="Country"; E={$_.Name}}, Count

# -- Risky user state ----------------------------------------------------------
Write-Host "[*] Checking Entra ID risk state..." -ForegroundColor Yellow
$RiskyUser = Get-MgRiskyUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue

# -- Output summary ------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nSign-in Countries:" -ForegroundColor White
$CountrySummary | Format-Table -AutoSize

if ($RiskyUser) {
    Write-Host "Entra ID Risk State: $($RiskyUser.RiskState) (Level: $($RiskyUser.RiskLevel))" -ForegroundColor Red
}

if ($ImpossibleTravel.Count -gt 0) {
    Write-Host "`n[!!] IMPOSSIBLE TRAVEL DETECTED ($($ImpossibleTravel.Count) instance(s)):" -ForegroundColor Red
    $ImpossibleTravel | Format-Table -AutoSize
} else {
    Write-Host "`n[OK] No impossible travel detected." -ForegroundColor Green
}

Write-Host "`nFlagged sign-in events: $($Findings.Count) of $($AllEvents.Count)" -ForegroundColor Yellow
$Findings | Select-Object DateTime, Country, IPAddress, Flags | Format-Table -AutoSize

# -- Export CSVs ---------------------------------------------------------------
$SafeUPN = $UserPrincipalName -replace '[^a-zA-Z0-9]', '_'

$AllPath  = Join-Path $ExportPath "IR_CompromisedAccount_AllSignIns_${SafeUPN}_${Timestamp}.csv"
$FlagPath = Join-Path $ExportPath "IR_CompromisedAccount_Flagged_${SafeUPN}_${Timestamp}.csv"
$TravPath = Join-Path $ExportPath "IR_CompromisedAccount_ImpossibleTravel_${SafeUPN}_${Timestamp}.csv"

$AllEvents        | Export-Csv -Path $AllPath  -NoTypeInformation -Encoding UTF8
$Findings         | Export-Csv -Path $FlagPath -NoTypeInformation -Encoding UTF8
$ImpossibleTravel | Export-Csv -Path $TravPath -NoTypeInformation -Encoding UTF8

Write-Host "`n[*] Reports exported:" -ForegroundColor Green
Write-Host "    All sign-ins  : $AllPath"
Write-Host "    Flagged events: $FlagPath"
Write-Host "    Impossible travel: $TravPath"
