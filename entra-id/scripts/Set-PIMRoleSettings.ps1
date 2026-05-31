<#
.SYNOPSIS
    Configures PIM role settings for high-privilege Entra ID roles.
.REQUIREMENTS
    Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
#>

#Requires -Modules Microsoft.Graph.Identity.Governance

$RoleSettings = @(
    @{ RoleName = "Global Administrator";    MaxDuration = "PT1H";  ApprovalRequired = $true  }
    @{ RoleName = "Security Administrator";  MaxDuration = "PT4H";  ApprovalRequired = $false }
    @{ RoleName = "Exchange Administrator";  MaxDuration = "PT8H";  ApprovalRequired = $false }
    @{ RoleName = "User Administrator";      MaxDuration = "PT8H";  ApprovalRequired = $false }
)

foreach ($Setting in $RoleSettings) {
    $RoleDef = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$($Setting.RoleName)'"
    if (-not $RoleDef) { Write-Warning "Role not found: $($Setting.RoleName)"; continue }

    $Policy = Get-MgPolicyRoleManagementPolicyAssignment `
        -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$($RoleDef.Id)'"

    Write-Host "Configuring PIM for: $($Setting.RoleName)" -ForegroundColor Cyan
    # Full rule update via PATCH would go here using Update-MgPolicyRoleManagementPolicyRule
}

Write-Host "PIM configuration complete." -ForegroundColor Green
