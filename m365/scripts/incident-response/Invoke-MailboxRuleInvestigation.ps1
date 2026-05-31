<#
.SYNOPSIS
    Incident Response -- Malicious Inbox Rule & Email Forwarding Investigation
    Detects attacker-created rules used to hide emails, exfiltrate data, or
    redirect mail to external addresses.

.DESCRIPTION
    Scans all mailboxes (or a target user) for:
      - External forwarding (SMTP forwarding to outside the tenant)
      - Inbox rules that delete, move, or redirect mail
      - Rules that forward to external addresses
      - Rules with suspicious keywords (invoice, payment, password, alert)
      - Hidden/disabled rules
      - Transport rules with external redirect actions

.PARAMETER UserPrincipalName
    Scope to a single user. If omitted, scans all mailboxes.

.PARAMETER TenantDomain
    Your primary tenant domain (e.g. contoso.com) used to identify external addresses.

.PARAMETER ExportPath
    Folder to write CSV reports. Defaults to current directory.

.REQUIREMENTS
    Connect-MgGraph -Scopes "Mail.ReadBasic.All", "MailboxSettings.Read"
    Connect-ExchangeOnline

.EXAMPLE
    .\Invoke-MailboxRuleInvestigation.ps1 -TenantDomain contoso.com
    .\Invoke-MailboxRuleInvestigation.ps1 -UserPrincipalName victim@contoso.com -TenantDomain contoso.com
#>

#Requires -Modules ExchangeOnlineManagement, Microsoft.Graph.Users

[CmdletBinding()]
param(
    [string] $UserPrincipalName = "",
    [Parameter(Mandatory)]
    [string] $TenantDomain,
    [string] $ExportPath = "."
)

Set-StrictMode -Version Latest
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Suspicious keywords commonly used in attacker-created rules
$SuspiciousKeywords = @(
    "invoice","payment","wire","transfer","bank","password","credential",
    "alert","notification","security","urgent","confidential","payroll",
    "w2","tax","verify","account","suspended","locked"
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 IR -- Mailbox Rule Investigation" -ForegroundColor Cyan
Write-Host "  Tenant : $TenantDomain" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# -- Get target mailboxes ------------------------------------------------------
Write-Host "[*] Fetching mailboxes..." -ForegroundColor Yellow

if ($UserPrincipalName) {
    $Mailboxes = Get-EXOMailbox -Identity $UserPrincipalName -PropertySets All
} else {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets All |
        Where-Object { $_.RecipientTypeDetails -in @("UserMailbox","SharedMailbox") }
}
Write-Host "    Mailboxes to scan: $($Mailboxes.Count)"

$ForwardingResults = [System.Collections.Generic.List[PSObject]]::new()
$RuleResults       = [System.Collections.Generic.List[PSObject]]::new()
$SuspiciousRules   = [System.Collections.Generic.List[PSObject]]::new()

$i = 0
foreach ($Mailbox in $Mailboxes) {
    $i++
    Write-Progress -Activity "Scanning mailboxes" -Status "$($Mailbox.UserPrincipalName)" `
        -PercentComplete (($i / $Mailboxes.Count) * 100)

    # -- Check SMTP forwarding -------------------------------------------------
    if ($Mailbox.ForwardingSmtpAddress -or $Mailbox.ForwardingAddress) {
        $FwdAddress = $Mailbox.ForwardingSmtpAddress ?? $Mailbox.ForwardingAddress
        $IsExternal = $FwdAddress -notlike "*@$TenantDomain*"

        $ForwardingResults.Add([PSCustomObject]@{
            Mailbox          = $Mailbox.UserPrincipalName
            ForwardingAddress = $FwdAddress
            DeliverToMailbox = $Mailbox.DeliverToMailboxAndForward
            IsExternal       = $IsExternal
            Severity         = if ($IsExternal) { "HIGH" } else { "MEDIUM" }
        })
    }

    # -- Check inbox rules -----------------------------------------------------
    $Rules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
    foreach ($Rule in $Rules) {
        $Suspicious = $false
        $Reasons    = [System.Collections.Generic.List[string]]::new()

        # External forward
        if ($Rule.ForwardTo -or $Rule.ForwardAsAttachmentTo) {
            $Addresses = @($Rule.ForwardTo) + @($Rule.ForwardAsAttachmentTo) | Where-Object { $_ }
            $ExternalFwd = $Addresses | Where-Object { $_ -notlike "*$TenantDomain*" }
            if ($ExternalFwd) {
                $Suspicious = $true
                $Reasons.Add("EXTERNAL_FORWARD:$($ExternalFwd -join ',')")
            }
        }

        # Redirect to external
        if ($Rule.RedirectTo) {
            $ExternalRedir = $Rule.RedirectTo | Where-Object { $_ -notlike "*$TenantDomain*" }
            if ($ExternalRedir) {
                $Suspicious = $true
                $Reasons.Add("EXTERNAL_REDIRECT:$($ExternalRedir -join ',')")
            }
        }

        # Delete action
        if ($Rule.DeleteMessage -eq $true) {
            $Suspicious = $true
            $Reasons.Add("DELETE_MESSAGE")
        }

        # Move to obscure folder
        if ($Rule.MoveToFolder -and $Rule.MoveToFolder -notlike "*Inbox*") {
            $Reasons.Add("MOVE_TO:$($Rule.MoveToFolder)")
        }

        # Mark as read (hiding from user)
        if ($Rule.MarkAsRead -eq $true) { $Reasons.Add("MARK_AS_READ") }

        # Suspicious keywords in rule conditions
        $RuleText = "$($Rule.SubjectContainsWords) $($Rule.BodyContainsWords) $($Rule.Name)" 
        foreach ($Kw in $SuspiciousKeywords) {
            if ($RuleText -imatch $Kw) {
                $Suspicious = $true
                $Reasons.Add("KEYWORD:$Kw")
                break
            }
        }

        # Disabled rule (hiding it)
        if ($Rule.Enabled -eq $false) { $Reasons.Add("DISABLED") }

        $RuleObj = [PSCustomObject]@{
            Mailbox          = $Mailbox.UserPrincipalName
            RuleName         = $Rule.Name
            RuleEnabled      = $Rule.Enabled
            Priority         = $Rule.Priority
            ForwardTo        = ($Rule.ForwardTo -join "; ")
            RedirectTo       = ($Rule.RedirectTo -join "; ")
            DeleteMessage    = $Rule.DeleteMessage
            MoveToFolder     = $Rule.MoveToFolder
            MarkAsRead       = $Rule.MarkAsRead
            SubjectKeywords  = ($Rule.SubjectContainsWords -join "; ")
            Suspicious       = $Suspicious
            Reasons          = ($Reasons -join " | ")
        }

        $RuleResults.Add($RuleObj)
        if ($Suspicious) { $SuspiciousRules.Add($RuleObj) }
    }
}
Write-Progress -Activity "Scanning mailboxes" -Completed

# -- Check transport rules for external redirect -------------------------------
Write-Host "`n[*] Checking transport rules for external routing..." -ForegroundColor Yellow
$TransportRules = Get-TransportRule | Where-Object {
    $_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo
}

$SuspiciousTransport = $TransportRules | Where-Object {
    $AllAddresses = @($_.RedirectMessageTo) + @($_.BlindCopyTo) + @($_.CopyTo) | Where-Object { $_ }
    $AllAddresses | Where-Object { $_ -notlike "*$TenantDomain*" }
} | Select-Object Name, State, Priority, RedirectMessageTo, BlindCopyTo, CopyTo, Description

# -- Output -------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  FINDINGS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[SMTP Forwarding] $($ForwardingResults.Count) mailbox(es) with forwarding configured:" -ForegroundColor $(if ($ForwardingResults.Count -gt 0) {"Red"} else {"Green"})
$ForwardingResults | Format-Table -AutoSize

Write-Host "`n[Inbox Rules] $($SuspiciousRules.Count) suspicious rule(s) found (of $($RuleResults.Count) total):" -ForegroundColor $(if ($SuspiciousRules.Count -gt 0) {"Red"} else {"Green"})
$SuspiciousRules | Select-Object Mailbox, RuleName, RuleEnabled, Reasons | Format-Table -AutoSize

Write-Host "`n[Transport Rules] $($SuspiciousTransport.Count) suspicious transport rule(s):" -ForegroundColor $(if ($SuspiciousTransport.Count -gt 0) {"Red"} else {"Green"})
$SuspiciousTransport | Format-Table -AutoSize

# -- Export -------------------------------------------------------------------
$FwdPath   = Join-Path $ExportPath "IR_MailboxRules_Forwarding_${Timestamp}.csv"
$RulesPath = Join-Path $ExportPath "IR_MailboxRules_AllRules_${Timestamp}.csv"
$SuspPath  = Join-Path $ExportPath "IR_MailboxRules_Suspicious_${Timestamp}.csv"

$ForwardingResults | Export-Csv -Path $FwdPath   -NoTypeInformation -Encoding UTF8
$RuleResults       | Export-Csv -Path $RulesPath  -NoTypeInformation -Encoding UTF8
$SuspiciousRules   | Export-Csv -Path $SuspPath   -NoTypeInformation -Encoding UTF8

Write-Host "`n[*] Reports exported:" -ForegroundColor Green
Write-Host "    Forwarding config : $FwdPath"
Write-Host "    All inbox rules   : $RulesPath"
Write-Host "    Suspicious rules  : $SuspPath"
