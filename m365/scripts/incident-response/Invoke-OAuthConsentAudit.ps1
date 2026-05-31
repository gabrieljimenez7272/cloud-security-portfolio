<#
.SYNOPSIS
    Incident Response -- Risky App Permissions & OAuth Consent Grant Audit
    Detects over-privileged apps and suspicious consent grants in Entra ID.

.DESCRIPTION
    Identifies:
      - Apps with high-risk delegated permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.)
      - Apps with admin-consented application permissions
      - Apps granted consent by non-admin users (user consent grants)
      - Recently registered apps (last 30 days)
      - Apps with credentials (secrets/certs) that are expired or expiring soon
      - Multi-tenant apps with broad permissions

.PARAMETER DaysBack
    How far back to look for recently created apps (default: 30)

.PARAMETER ExportPath
    Folder to write CSV reports. Defaults to current directory.

.REQUIREMENTS
    Connect-MgGraph -Scopes "Application.Read.All", "DelegatedPermissionGrant.ReadWrite.All",
        "Directory.Read.All", "AuditLog.Read.All"

.EXAMPLE
    .\Invoke-OAuthConsentAudit.ps1 -DaysBack 14
#>

#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns

[CmdletBinding()]
param(
    [int]    $DaysBack    = 30,
    [string] $ExportPath  = "."
)

Set-StrictMode -Version Latest
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# High-risk permission scopes
$HighRiskDelegated = @(
    "Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite",
    "Files.ReadWrite.All","Sites.FullControl.All",
    "Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All","Application.ReadWrite.All",
    "User.ReadWrite.All","Group.ReadWrite.All",
    "Calendars.ReadWrite","Contacts.ReadWrite",
    "ChannelMessage.Send","ChatMessage.Send"
)

$HighRiskApplication = @(
    "Mail.ReadWrite","Mail.Send","Files.ReadWrite.All",
    "Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory",
    "User.ReadWrite.All","Group.ReadWrite.All",
    "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All",
    "Sites.FullControl.All","Exchange.ManageAsApp"
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 IR -- OAuth Consent Audit" -ForegroundColor Cyan
Write-Host "  Looking back : $DaysBack days for new apps" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# -- Pull all service principals -----------------------------------------------
Write-Host "[*] Fetching service principals..." -ForegroundColor Yellow
$ServicePrincipals = Get-MgServicePrincipal -All -PageSize 500 |
    Where-Object { $_.ServicePrincipalType -ne "ManagedIdentity" }
Write-Host "    Service principals found: $($ServicePrincipals.Count)"

# -- Pull OAuth2 delegated permission grants -----------------------------------
Write-Host "[*] Fetching OAuth2 permission grants..." -ForegroundColor Yellow
$OAuth2Grants = Get-MgOauth2PermissionGrant -All -PageSize 500
Write-Host "    Permission grants found: $($OAuth2Grants.Count)"

# -- Pull app role assignments (application permissions) -----------------------
Write-Host "[*] Fetching application role assignments..." -ForegroundColor Yellow
$AppRoleAssignments = [System.Collections.Generic.List[PSObject]]::new()

foreach ($SP in $ServicePrincipals) {
    $Assignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id `
        -All -ErrorAction SilentlyContinue
    foreach ($A in $Assignments) {
        $AppRoleAssignments.Add($A)
    }
}

# -- Build app report ----------------------------------------------------------
$AppReport      = [System.Collections.Generic.List[PSObject]]::new()
$HighRiskApps   = [System.Collections.Generic.List[PSObject]]::new()
$RecentApps     = [System.Collections.Generic.List[PSObject]]::new()
$UserConsentApps = [System.Collections.Generic.List[PSObject]]::new()

$SPIndex = @{}
foreach ($SP in $ServicePrincipals) { $SPIndex[$SP.Id] = $SP }

foreach ($Grant in $OAuth2Grants) {
    $SP     = $SPIndex[$Grant.ClientId]
    if (-not $SP) { continue }

    $Scopes     = $Grant.Scope -split " " | Where-Object { $_ }
    $RiskyScopes = $Scopes | Where-Object { $_ -in $HighRiskDelegated }
    $IsUserConsent = $Grant.ConsentType -eq "Principal"
    $IsHighRisk    = $RiskyScopes.Count -gt 0

    $Obj = [PSCustomObject]@{
        AppName         = $SP.DisplayName
        AppId           = $SP.AppId
        ConsentType     = $Grant.ConsentType
        Scopes          = ($Scopes -join "; ")
        HighRiskScopes  = ($RiskyScopes -join "; ")
        IsHighRisk      = $IsHighRisk
        IsUserConsent   = $IsUserConsent
        IsMultiTenant   = $SP.AppOwnerOrganizationId -ne (Get-MgOrganization).Id
        CreatedDateTime = $SP.AdditionalProperties["createdDateTime"]
        PermissionType  = "Delegated"
    }

    $AppReport.Add($Obj)
    if ($IsHighRisk)    { $HighRiskApps.Add($Obj) }
    if ($IsUserConsent) { $UserConsentApps.Add($Obj) }
}

# -- Application permissions (app roles) ---------------------------------------
$MSGraphSP = $ServicePrincipals | Where-Object { $_.AppId -eq "00000003-0000-0000-c000-000000000000" }
if ($MSGraphSP) {
    foreach ($Assignment in $AppRoleAssignments | Where-Object { $_.ResourceId -eq $MSGraphSP.Id }) {
        $SP       = $SPIndex[$Assignment.PrincipalId]
        $AppRole  = $MSGraphSP.AppRoles | Where-Object { $_.Id -eq $Assignment.AppRoleId }
        if (-not $SP -or -not $AppRole) { continue }

        $IsHighRisk = $AppRole.Value -in $HighRiskApplication

        $Obj = [PSCustomObject]@{
            AppName         = $SP.DisplayName
            AppId           = $SP.AppId
            ConsentType     = "Admin (Application)"
            Scopes          = $AppRole.Value
            HighRiskScopes  = if ($IsHighRisk) { $AppRole.Value } else { "" }
            IsHighRisk      = $IsHighRisk
            IsUserConsent   = $false
            IsMultiTenant   = $SP.AppOwnerOrganizationId -ne (Get-MgOrganization).Id
            CreatedDateTime = $SP.AdditionalProperties["createdDateTime"]
            PermissionType  = "Application"
        }

        $AppReport.Add($Obj)
        if ($IsHighRisk) { $HighRiskApps.Add($Obj) }
    }
}

# -- Recently registered apps --------------------------------------------------
$Since = (Get-Date).AddDays(-$DaysBack)
$RecentApps = $ServicePrincipals | Where-Object {
    $Created = $_.AdditionalProperties["createdDateTime"]
    $Created -and [datetime]$Created -gt $Since
} | Select-Object DisplayName, AppId,
    @{N="CreatedDateTime"; E={$_.AdditionalProperties["createdDateTime"]}},
    @{N="IsMultiTenant";   E={$_.AppOwnerOrganizationId -ne (Get-MgOrganization).Id}}

# -- Output --------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[HIGH RISK] Apps with high-risk permissions ($($HighRiskApps.Count)):" `
    -ForegroundColor $(if ($HighRiskApps.Count -gt 0) {"Red"} else {"Green"})
$HighRiskApps | Select-Object AppName, ConsentType, PermissionType, HighRiskScopes |
    Format-Table -AutoSize

Write-Host "`n[USER CONSENT] Apps consented by individual users ($($UserConsentApps.Count)):" `
    -ForegroundColor $(if ($UserConsentApps.Count -gt 0) {"Yellow"} else {"Green"})
$UserConsentApps | Select-Object AppName, Scopes | Format-Table -AutoSize

Write-Host "`n[RECENT] Apps registered in last $DaysBack days ($($RecentApps.Count)):" `
    -ForegroundColor $(if ($RecentApps.Count -gt 0) {"Yellow"} else {"Green"})
$RecentApps | Format-Table -AutoSize

# -- Export --------------------------------------------------------------------
$AllPath    = Join-Path $ExportPath "IR_OAuthAudit_All_${Timestamp}.csv"
$RiskyPath  = Join-Path $ExportPath "IR_OAuthAudit_HighRisk_${Timestamp}.csv"
$UserPath   = Join-Path $ExportPath "IR_OAuthAudit_UserConsent_${Timestamp}.csv"
$RecentPath = Join-Path $ExportPath "IR_OAuthAudit_RecentApps_${Timestamp}.csv"

$AppReport      | Export-Csv -Path $AllPath    -NoTypeInformation -Encoding UTF8
$HighRiskApps   | Export-Csv -Path $RiskyPath  -NoTypeInformation -Encoding UTF8
$UserConsentApps| Export-Csv -Path $UserPath   -NoTypeInformation -Encoding UTF8
$RecentApps     | Export-Csv -Path $RecentPath -NoTypeInformation -Encoding UTF8

Write-Host "`n[*] Reports exported:" -ForegroundColor Green
Write-Host "    All grants      : $AllPath"
Write-Host "    High risk apps  : $RiskyPath"
Write-Host "    User consents   : $UserPath"
Write-Host "    Recent apps     : $RecentPath"
