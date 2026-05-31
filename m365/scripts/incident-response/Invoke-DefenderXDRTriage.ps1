<#
.SYNOPSIS
    Incident Response -- Defender XDR Incident Triage & Investigation
    Pulls active incidents, correlates alerts, and produces a triage report.

.DESCRIPTION
    For each active Defender XDR incident:
      - Pulls all correlated alerts and their evidence
      - Identifies affected users, devices, and mailboxes
      - Maps alerts to MITRE ATT&CK tactics
      - Flags high-severity unassigned incidents
      - Correlates alerts across the same user or device
      - Exports a triage package ready for analyst handoff

.PARAMETER Severity
    Filter by minimum severity: High, Medium, Low (default: High,Medium)

.PARAMETER DaysBack
    How many days back to pull incidents (default: 7)

.PARAMETER IncidentId
    Pull a single specific incident by ID.

.PARAMETER ExportPath
    Folder to write CSV reports. Defaults to current directory.

.REQUIREMENTS
    Connect-MgGraph -Scopes "SecurityIncident.Read.All", "SecurityAlert.Read.All"

.EXAMPLE
    .\Invoke-DefenderXDRTriage.ps1 -Severity High -DaysBack 3
    .\Invoke-DefenderXDRTriage.ps1 -IncidentId "12345"
#>

#Requires -Modules Microsoft.Graph.Security

[CmdletBinding()]
param(
    [string[]] $Severity   = @("high","medium"),
    [int]      $DaysBack   = 7,
    [string]   $IncidentId = "",
    [string]   $ExportPath = "."
)

Set-StrictMode -Version Latest
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 IR -- Defender XDR Triage" -ForegroundColor Cyan
Write-Host "  Severity : $($Severity -join ', ')" -ForegroundColor Cyan
Write-Host "  Window   : Last $DaysBack days" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# -- Pull incidents ------------------------------------------------------------
Write-Host "[*] Fetching incidents..." -ForegroundColor Yellow

$Since = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

if ($IncidentId) {
    $Incidents = @(Get-MgSecurityIncident -IncidentId $IncidentId)
} else {
    $SevFilter = ($Severity | ForEach-Object { "severity eq '$_'" }) -join " or "
    $Filter    = "($SevFilter) and createdDateTime ge $Since"
    $Incidents = Get-MgSecurityIncident -Filter $Filter -All | Sort-Object CreatedDateTime -Descending
}

Write-Host "    Incidents found: $($Incidents.Count)"

if ($Incidents.Count -eq 0) {
    Write-Host "    No incidents found matching criteria." -ForegroundColor Green
    exit 0
}

# -- Process each incident -----------------------------------------------------
$IncidentReport  = [System.Collections.Generic.List[PSObject]]::new()
$AlertReport     = [System.Collections.Generic.List[PSObject]]::new()
$EvidenceReport  = [System.Collections.Generic.List[PSObject]]::new()
$AffectedReport  = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Incident in $Incidents) {
    Write-Host "`n  [*] Processing incident: $($Incident.DisplayName) (ID: $($Incident.Id))" -ForegroundColor Yellow

    # -- Correlated alerts -----------------------------------------------------
    $Alerts = Get-MgSecurityIncidentAlert -IncidentId $Incident.Id -All -ErrorAction SilentlyContinue

    $Tactics     = ($Alerts.MitreTechniques | Where-Object { $_ } | Sort-Object -Unique) -join "; "
    $Categories  = ($Alerts.Category       | Where-Object { $_ } | Sort-Object -Unique) -join "; "
    $Unassigned  = -not $Incident.AssignedTo
    $IsEscalated = $Incident.Severity -eq "high" -and $Unassigned

    $IncidentReport.Add([PSCustomObject]@{
        IncidentId      = $Incident.Id
        Title           = $Incident.DisplayName
        Severity        = $Incident.Severity
        Status          = $Incident.Status
        AssignedTo      = $Incident.AssignedTo
        CreatedDateTime = $Incident.CreatedDateTime
        LastUpdated     = $Incident.LastUpdateDateTime
        AlertCount      = $Alerts.Count
        Tactics         = $Tactics
        Categories      = $Categories
        Tags            = ($Incident.Tags -join "; ")
        NeedsEscalation = $IsEscalated
        Classification  = $Incident.Classification
        Determination   = $Incident.Determination
    })

    # -- Per-alert detail -------------------------------------------------------
    foreach ($Alert in $Alerts) {
        $AlertReport.Add([PSCustomObject]@{
            IncidentId      = $Incident.Id
            AlertId         = $Alert.Id
            Title           = $Alert.Title
            Severity        = $Alert.Severity
            Status          = $Alert.Status
            Category        = $Alert.Category
            MitreTechniques = ($Alert.MitreTechniques -join "; ")
            DetectionSource = $Alert.DetectionSource
            ServiceSource   = $Alert.ServiceSource
            CreatedDateTime = $Alert.CreatedDateTime
            FirstActivity   = $Alert.FirstActivityDateTime
            LastActivity    = $Alert.LastActivityDateTime
            Description     = $Alert.Description
        })

        # -- Evidence -------------------------------------------------------------
        foreach ($Evidence in $Alert.Evidence) {
            $EvidenceReport.Add([PSCustomObject]@{
                IncidentId     = $Incident.Id
                AlertId        = $Alert.Id
                EvidenceType   = $Evidence.AdditionalProperties["@odata.type"]
                RemediationStatus = $Evidence.RemediationStatus
                Verdict        = $Evidence.Verdict
                EntityDetail   = ($Evidence.AdditionalProperties | ConvertTo-Json -Compress -Depth 2)
            })
        }
    }

    # -- Affected entities -------------------------------------------------------
    foreach ($Entity in $Incident.Comments) {
        # Affected users
        foreach ($User in $Incident.AdditionalProperties["impactedUsers"]) {
            $AffectedReport.Add([PSCustomObject]@{
                IncidentId  = $Incident.Id
                EntityType  = "User"
                EntityName  = $User["userPrincipalName"]
                RiskScore   = $User["riskScore"]
                Tags        = ($User["tags"] -join "; ")
            })
        }
    }

    # Simpler affected entity pull from alert evidence
    $AffectedUsers   = $Alerts.Evidence | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*userAccount*" }
    $AffectedDevices = $Alerts.Evidence | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*device*" }
    $AffectedMail    = $Alerts.Evidence | Where-Object { $_.AdditionalProperties["@odata.type"] -like "*mailbox*" }

    Write-Host "      Alerts   : $($Alerts.Count)"
    Write-Host "      Tactics  : $Tactics"
    Write-Host "      Users    : $($AffectedUsers.Count)"
    Write-Host "      Devices  : $($AffectedDevices.Count)"
    Write-Host "      Mailboxes: $($AffectedMail.Count)"
    if ($IsEscalated) {
        Write-Host "      [!!] HIGH severity + UNASSIGNED -- needs immediate triage" -ForegroundColor Red
    }
}

# -- MITRE tactic summary ------------------------------------------------------
$TacticSummary = $AlertReport |
    Where-Object { $_.MitreTechniques } |
    ForEach-Object { $_.MitreTechniques -split "; " } |
    Group-Object | Sort-Object Count -Descending |
    Select-Object @{N="Technique"; E={$_.Name}}, Count

# -- Output --------------------------------------------------------------------
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  TRIAGE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nIncident Overview:" -ForegroundColor White
$IncidentReport | Select-Object IncidentId, Title, Severity, Status, AssignedTo,
    AlertCount, NeedsEscalation | Format-Table -AutoSize

$NeedsEsc = $IncidentReport | Where-Object { $_.NeedsEscalation }
if ($NeedsEsc.Count -gt 0) {
    Write-Host "`n[!!] $($NeedsEsc.Count) HIGH severity unassigned incident(s) need immediate attention:" -ForegroundColor Red
    $NeedsEsc | Select-Object IncidentId, Title, CreatedDateTime | Format-Table -AutoSize
}

Write-Host "`nMITRE ATT&CK Techniques Observed:" -ForegroundColor White
$TacticSummary | Format-Table -AutoSize

# -- Export --------------------------------------------------------------------
$IncPath  = Join-Path $ExportPath "IR_DefenderXDR_Incidents_${Timestamp}.csv"
$AltPath  = Join-Path $ExportPath "IR_DefenderXDR_Alerts_${Timestamp}.csv"
$EvPath   = Join-Path $ExportPath "IR_DefenderXDR_Evidence_${Timestamp}.csv"

$IncidentReport | Export-Csv -Path $IncPath -NoTypeInformation -Encoding UTF8
$AlertReport    | Export-Csv -Path $AltPath -NoTypeInformation -Encoding UTF8
$EvidenceReport | Export-Csv -Path $EvPath  -NoTypeInformation -Encoding UTF8

Write-Host "`n[*] Triage package exported:" -ForegroundColor Green
Write-Host "    Incidents : $IncPath"
Write-Host "    Alerts    : $AltPath"
Write-Host "    Evidence  : $EvPath"
