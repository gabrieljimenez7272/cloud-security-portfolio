<#
.SYNOPSIS
    Audits Self-Service Password Reset (SSPR) configuration and registration coverage.
    Reports which users are registered, unregistered, and SSPR policy settings.

.REQUIREMENTS
    Connect-MgGraph -Scopes "Policy.Read.All", "Reports.Read.All", "User.Read.All"

.EXAMPLE
    .\Get-SSPRAuditReport.ps1
#>

#Requires -Modules Microsoft.Graph.Reports, Microsoft.Graph.Identity.SignIns

Write-Host "Fetching SSPR configuration and registration data..." -ForegroundColor Cyan

# -- SSPR Policy Settings -------------------------------------------------------
$AuthPolicy = Get-MgPolicyAuthenticationMethodPolicy

Write-Host "`n== SSPR Policy ==" -ForegroundColor Cyan
Write-Host "  Policy Version    : $($AuthPolicy.PolicyVersion)"
Write-Host "  Last Modified     : $($AuthPolicy.LastModifiedDateTime)"
Write-Host "  Migration State   : $($AuthPolicy.PolicyMigrationState)"

# -- SSPR Registration Report ---------------------------------------------------
Write-Host "`nFetching registration details (may take a moment)..." -ForegroundColor Cyan

$RegistrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All

$Registered   = $RegistrationDetails | Where-Object { $_.IsSsprRegistered -eq $true }
$Unregistered = $RegistrationDetails | Where-Object { $_.IsSsprRegistered -eq $false }
$SSPREnabled  = $RegistrationDetails | Where-Object { $_.IsSsprEnabled    -eq $true }
$MFACapable   = $RegistrationDetails | Where-Object { $_.IsMfaCapable     -eq $true }

$Total = $RegistrationDetails.Count

Write-Host "`n== SSPR Registration Summary ==" -ForegroundColor Cyan
Write-Host "  Total users       : $Total"
Write-Host "  SSPR registered   : $($Registered.Count) ($([math]::Round($Registered.Count/$Total*100,1))%)" -ForegroundColor Green
Write-Host "  SSPR unregistered : $($Unregistered.Count) ($([math]::Round($Unregistered.Count/$Total*100,1))%)" -ForegroundColor Yellow
Write-Host "  SSPR enabled      : $($SSPREnabled.Count)"
Write-Host "  MFA capable       : $($MFACapable.Count)"

# -- Unregistered Users ---------------------------------------------------------
if ($Unregistered.Count -gt 0) {
    Write-Host "`n== Users NOT Registered for SSPR (first 25) ==" -ForegroundColor Yellow
    $Unregistered | Select-Object -First 25 |
        Select-Object UserDisplayName, UserPrincipalName, DefaultMfaMethod |
        Format-Table -AutoSize
}

# -- Method Breakdown -----------------------------------------------------------
Write-Host "`n== Auth Method Breakdown ==" -ForegroundColor Cyan
$RegistrationDetails |
    Group-Object DefaultMfaMethod |
    Sort-Object Count -Descending |
    Select-Object @{N="Method"; E={$_.Name}}, Count |
    Format-Table -AutoSize
