<#
.SYNOPSIS
    Reports guest accounts in Entra ID that haven't signed in for 90+ days.
.REQUIREMENTS
    Microsoft.Graph PowerShell module
    Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Reports

$StaleThresholdDays = 90
$CutoffDate = (Get-Date).AddDays(-$StaleThresholdDays)

$StaleGuests = Get-MgUser -Filter "userType eq 'Guest'" -All `
    -Property DisplayName, UserPrincipalName, SignInActivity, CreatedDateTime |
    Where-Object {
        ($_.SignInActivity.LastSignInDateTime -lt $CutoffDate) -or
        ($null -eq $_.SignInActivity.LastSignInDateTime -and $_.CreatedDateTime -lt $CutoffDate)
    } |
    Select-Object DisplayName, UserPrincipalName,
        @{N="LastSignIn"; E={$_.SignInActivity.LastSignInDateTime}},
        CreatedDateTime

if ($StaleGuests) {
    Write-Host "Found $($StaleGuests.Count) stale guest account(s):" -ForegroundColor Yellow
    $StaleGuests | Format-Table -AutoSize
} else {
    Write-Host "No stale guest accounts found." -ForegroundColor Green
}
