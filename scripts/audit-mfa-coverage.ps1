<#
.SYNOPSIS
    Reports Entra ID users without any MFA method registered.
.REQUIREMENTS
    Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All"
#>

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

$AllUsers   = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType
$NoMFAUsers = @()

foreach ($User in $AllUsers | Where-Object { $_.UserType -eq "Member" }) {
    $Methods = Get-MgUserAuthenticationMethod -UserId $User.Id
    $HasMFA  = $Methods | Where-Object {
        $_.AdditionalProperties["@odata.type"] -in @(
            "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
            "#microsoft.graph.phoneAuthenticationMethod",
            "#microsoft.graph.fido2AuthenticationMethod",
            "#microsoft.graph.softwareOathAuthenticationMethod"
        )
    }
    if (-not $HasMFA) {
        $NoMFAUsers += $User | Select-Object DisplayName, UserPrincipalName
    }
}

if ($NoMFAUsers) {
    Write-Host "Users without MFA ($($NoMFAUsers.Count)):" -ForegroundColor Yellow
    $NoMFAUsers | Format-Table -AutoSize
} else {
    Write-Host "All users have at least one MFA method registered." -ForegroundColor Green
}
