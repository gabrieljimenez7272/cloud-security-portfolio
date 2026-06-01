<#
.SYNOPSIS
    Incident Response -- Compromised User Account Investigation (FIXED VERSION)

.DESCRIPTION
    Analyzes Entra ID sign-in logs for suspicious activity:
    - Impossible travel
    - MFA bypass
    - Legacy authentication
    - High/medium risk sign-ins
    - Outside business hours
    - Failed sign-ins

.REQUIREMENTS
    Connect-MgGraph -Scopes "AuditLog.Read.All", "User.Read.All", "IdentityRiskyUser.Read.All"
#>

#Requires -Modules Microsoft.Graph.Users
#Requires -Modules Microsoft.Graph.Identity.SignIns

[CmdletBinding()]
param(
    [string] $UserPrincipalName = "",
    [int] $DaysBack = 30,
    [int] $BusinessHoursStart = 7,
    [int] $BusinessHoursEnd = 19,
    [string] $ExportPath = "."
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# -------------------------------------------------------------------
# Prompt if needed
# -------------------------------------------------------------------
if (-not $UserPrincipalName) {
    $UserPrincipalName = Read-Host "Enter UPN to investigate"
}

Write-Host "`n==== M365 IR - Account Investigation ====" -ForegroundColor Cyan
Write-Host "Target : $UserPrincipalName"
Write-Host "Window : Last $DaysBack days"
Write-Host "=========================================`n"

# -------------------------------------------------------------------
# Ensure export folder exists
# -------------------------------------------------------------------
if (-not (Test-Path $ExportPath)) {
    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
}

# -------------------------------------------------------------------
# Get user (FIXED - no -UserId with UPN)
# -------------------------------------------------------------------
Write-Host "[*] Fetching user..." -ForegroundColor Yellow

$User = Get-MgUser `
    -Filter "userPrincipalName eq '$UserPrincipalName'" `
    -ConsistencyLevel eventual `
    -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,UserType

$User = @($User) | Select-Object -First 1

if (-not $User) {
    throw "User not found: $UserPrincipalName"
}

Write-Host "    Name   : $($User.DisplayName)"
Write-Host "    Enabled: $($User.AccountEnabled)"
Write-Host "    Type   : $($User.UserType)"

# Optional last sign-in (safe)
try {
    $UserSignIn = Get-MgUser -UserId $User.Id -Property SignInActivity
    Write-Host "    LastSignIn: $($UserSignIn.SignInActivity.LastSignInDateTime)"
} catch {
    Write-Host "    LastSignIn: Not available"
}

# -------------------------------------------------------------------
# Pull sign-in logs
# -------------------------------------------------------------------
Write-Host "`n[*] Pulling sign-in logs..." -ForegroundColor Yellow

$Since = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

$SignIns = Get-MgAuditLogSignIn `
    -Filter "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $Since" `
    -All

$SignIns = @($SignIns)

Write-Host "    Sign-ins found: $($SignIns.Count)"

if ($SignIns.Count -eq 0) {
    Write-Host "No sign-ins found." -ForegroundColor Yellow
    exit 0
}

# -------------------------------------------------------------------
# Analysis containers
# -------------------------------------------------------------------
$AllEvents = [System.Collections.Generic.List[object]]::new()
$Findings  = [System.Collections.Generic.List[object]]::new()

# -------------------------------------------------------------------
# Analyze sign-ins
# -------------------------------------------------------------------
foreach ($s in $SignIns) {

    $flags = New-Object System.Collections.Generic.List[string]

    $country = $s.Location.CountryOrRegion
    $city    = $s.Location.City

    # MFA bypass
    if ($s.AuthenticationRequirement -eq "singleFactorAuthentication" -and
        $s.ConditionalAccessStatus -ne "notApplied") {
        $flags.Add("MFA_BYPASS")
    }

    # Legacy auth
    $legacy = @("SMTP","POP3","IMAP4","MAPI","Exchange ActiveSync","Other clients")
    if ($s.ClientAppUsed -in $legacy) {
        $flags.Add("LEGACY:$($s.ClientAppUsed)")
    }

    # Risk
    if ($s.RiskLevelDuringSignIn -in @("high","medium")) {
        $flags.Add("RISK:$($s.RiskLevelDuringSignIn)")
    }

    # Business hours (UTC)
    $hour = ([datetime]$s.CreatedDateTime).Hour
    if ($hour -lt $BusinessHoursStart -or $hour -ge $BusinessHoursEnd) {
        $flags.Add("OUTSIDE_HOURS")
    }

    # Failure
    if ($s.Status.ErrorCode -ne 0) {
        $flags.Add("FAILED:$($s.Status.FailureReason)")
    }

    $obj = [pscustomobject]@{
        DateTime       = $s.CreatedDateTime
        App            = $s.AppDisplayName
        ClientApp      = $s.ClientAppUsed
        IPAddress      = $s.IpAddress
        Country        = $country
        City           = $city
        Risk           = $s.RiskLevelDuringSignIn
        MFARequirement = $s.AuthenticationRequirement
        Status         = if ($s.Status.ErrorCode -eq 0) { "Success" } else { "Fail" }
        FailureReason  = $s.Status.FailureReason
        Flags          = ($flags -join " | ")
        CorrelationId  = $s.CorrelationId
    }

    $AllEvents.Add($obj)

    if ($flags.Count -gt 0) {
        $Findings.Add($obj)
    }
}

# -------------------------------------------------------------------
# Impossible travel
# -------------------------------------------------------------------
Write-Host "`n[*] Checking impossible travel..." -ForegroundColor Yellow

$success = $AllEvents | Where-Object Status -eq "Success" | Sort-Object DateTime
$impossible = [System.Collections.Generic.List[object]]::new()

for ($i = 1; $i -lt $success.Count; $i++) {

    $a = $success[$i-1]
    $b = $success[$i]

    if ($a.Country -and $b.Country -and $a.Country -ne $b.Country) {

        $diff = ([datetime]$b.DateTime - [datetime]$a.DateTime).TotalMinutes

        if ($diff -le 60) {
            $impossible.Add([pscustomobject]@{
                FromTime   = $a.DateTime
                FromCountry= $a.Country
                ToTime     = $b.DateTime
                ToCountry  = $b.Country
                Minutes    = [math]::Round($diff,1)
            })
        }
    }
}

# -------------------------------------------------------------------
# Country summary
# -------------------------------------------------------------------
$countrySummary = $AllEvents |
    Where-Object Country |
    Group-Object Country |
    Sort-Object Count -Descending |
    Select-Object Name, Count

# -------------------------------------------------------------------
# Risky user
# -------------------------------------------------------------------
Write-Host "[*] Checking risky user..." -ForegroundColor Yellow

$RiskyUser = $null
try {
    $RiskyUser = Get-MgRiskyUser -Filter "userPrincipalName eq '$UserPrincipalName'"
} catch {}

# -------------------------------------------------------------------
# Output
# -------------------------------------------------------------------
Write-Host "`n==== SUMMARY ====" -ForegroundColor Cyan

$countrySummary | Format-Table -AutoSize

if ($RiskyUser) {
    Write-Host "Risk State: $($RiskyUser.RiskState) | Level: $($RiskyUser.RiskLevel)" -ForegroundColor Red
}

if ($impossible.Count -gt 0) {
    Write-Host "`nIMPOSIBLE TRAVEL DETECTED: $($impossible.Count)" -ForegroundColor Red
    $impossible | Format-Table -AutoSize
}
else {
    Write-Host "`nNo impossible travel detected." -ForegroundColor Green
}

Write-Host "`nFindings: $($Findings.Count) / $($AllEvents.Count)"

# -------------------------------------------------------------------
# Export
# -------------------------------------------------------------------
$safe = $UserPrincipalName -replace '[^a-zA-Z0-9]', '_'

$AllPath   = Join-Path $ExportPath "AllSignIns_${safe}_${Timestamp}.csv"
$FindPath  = Join-Path $ExportPath "Findings_${safe}_${Timestamp}.csv"
$ImpPath   = Join-Path $ExportPath "ImpossibleTravel_${safe}_${Timestamp}.csv"

$AllEvents | Export-Csv $AllPath -NoTypeInformation
$Findings  | Export-Csv $FindPath -NoTypeInformation
$impossible| Export-Csv $ImpPath -NoTypeInformation

Write-Host "`nExports:"
Write-Host $AllPath
Write-Host $FindPath
Write-Host $ImpPath
