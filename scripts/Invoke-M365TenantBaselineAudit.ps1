<#
.SYNOPSIS
    Read-only Microsoft 365 tenant baseline audit.

.DESCRIPTION
    Collects Microsoft 365 tenant baseline information using Microsoft Graph PowerShell
    and optional Exchange Online PowerShell. The script is designed for Global Reader
    style read-only audits. It does not change tenant configuration.

.NOTES
    Public-safe portfolio script. Review reports before sharing.
#>

[CmdletBinding()]
param(
    [string[]]$Scopes = @(
        "Organization.Read.All",
        "Directory.Read.All",
        "User.Read.All",
        "Group.Read.All",
        "Policy.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
        "RoleManagement.Read.Directory",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
        "Reports.Read.All"
    ),

    [string]$OutputPath = (Get-Location).Path,

    [string]$TenantId,

    [string]$ClientId,

    [ValidateSet("Sanitized", "Full")]
    [string]$PrivacyMode = "Sanitized",

    [switch]$IncludeExchangeOnline,

    [switch]$SkipGraphConnect
)

$ErrorActionPreference = "Stop"

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet("PASS", "INFO", "WARN", "FAIL", "SKIPPED")][string]$Status,
        [Parameter(Mandatory)][string]$Detail
    )

    [pscustomobject]@{
        Area   = $Area
        Check  = $Check
        Status = $Status
        Detail = $Detail
    }
}

function Invoke-GraphGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Area = "Graph",
        [string]$Name = $Uri,
        [switch]$CountOnly
    )

    try {
        $Headers = @{}
        if ($Uri -match '\$count|ConsistencyLevel') {
            $Headers["ConsistencyLevel"] = "eventual"
        }

        if ($Headers.Count -gt 0) {
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $Headers -ErrorAction Stop
        }

        return Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
    }
    catch {
        [pscustomobject]@{
            __Skipped = $true
            Area      = $Area
            Name      = $Name
            Error     = $_.Exception.Message
        }
    }
}

function Get-GraphCollectionCount {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Area = "Graph",
        [string]$Name = $Uri
    )

    $Result = Invoke-GraphGet -Uri $Uri -Area $Area -Name $Name

    if ($Result.__Skipped) {
        return $Result
    }

    if ($null -ne $Result.'@odata.count') {
        return [int]$Result.'@odata.count'
    }

    if ($null -ne $Result.value) {
        return @($Result.value).Count
    }

    if ($Result -is [int]) {
        return $Result
    }

    return 0
}

function ConvertTo-SafeText {
    param([AllowNull()][object]$Value)

    $Text = [string]$Value

    if ($PrivacyMode -eq "Full") {
        return $Text
    }

    $Text = $Text -replace '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<tenant-guid>'
    $Text = $Text -replace '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<email>'
    $Text = $Text -replace '\b[A-Za-z0-9-]+\.onmicrosoft\.com\b', '<tenant>.onmicrosoft.com'

    return $Text
}

function Assert-ReadOnlyGraphContext {
    [CmdletBinding()]
    param(
        [string[]]$ExpectedReadOnlyScopes = @()
    )

    $Context = Get-MgContext

    if (-not $Context) {
        throw "Microsoft Graph context was not found. Connect-MgGraph must complete before read-only scope validation."
    }

    $Scopes = @($Context.Scopes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $UnsafeScopes = $Scopes |
        Where-Object {
            $_ -match "Write" -or
            $_ -match "ReadWrite" -or
            $_ -match "FullControl" -or
            $_ -match "AccessAsUser" -or
            $_ -match "RoleManagement\.ReadWrite" -or
            $_ -match "Policy\.ReadWrite"
        } |
        Sort-Object -Unique

    if ($UnsafeScopes.Count -gt 0) {
        throw @"
Unsafe Microsoft Graph context detected.

This audit is designed for read-only execution.

The current Microsoft Graph session includes write-capable or broad delegated scopes:

$($UnsafeScopes -join "`n")

Stop.

Use a dedicated read-only app registration or reconnect with a Microsoft Graph context that contains only read scopes.
Recommended:
Connect-MgGraph -ClientId <READ_ONLY_APP_CLIENT_ID> -TenantId <TENANT_ID> -ContextScope Process -Scopes <read-only scopes>
"@
    }

    $UnexpectedScopes = $Scopes |
        Where-Object {
            $_ -notin $ExpectedReadOnlyScopes -and
            $_ -notin @("openid", "profile", "email", "offline_access")
        } |
        Sort-Object -Unique

    [pscustomobject]@{
        Account          = $Context.Account
        TenantId         = $Context.TenantId
        ContextScope     = $Context.ContextScope
        Scopes           = $Scopes
        UnexpectedScopes = $UnexpectedScopes
    }
}

function Add-SectionStatus {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Area,
        [string]$Check,
        $Value,
        [string]$SuccessDetail
    )

    if ($Value.__Skipped) {
        $Findings.Add((New-Finding -Area $Area -Check $Check -Status "SKIPPED" -Detail (ConvertTo-SafeText $Value.Error)))
    }
    else {
        $Findings.Add((New-Finding -Area $Area -Check $Check -Status "PASS" -Detail $SuccessDetail))
    }
}

function New-HtmlReport {
    param(
        [array]$Findings,
        [hashtable]$Data,
        [string]$GeneratedAt
    )

    $Rows = foreach ($Finding in ($Findings | Sort-Object Area, Check)) {
        $StatusClass = ([string]$Finding.Status).ToLowerInvariant()
        "<tr><td>$([System.Net.WebUtility]::HtmlEncode($Finding.Area))</td><td>$([System.Net.WebUtility]::HtmlEncode($Finding.Check))</td><td><span class='status $StatusClass'>$([System.Net.WebUtility]::HtmlEncode($Finding.Status))</span></td><td>$([System.Net.WebUtility]::HtmlEncode($Finding.Detail))</td></tr>"
    }

    $Totals = $Findings | Group-Object Status | Sort-Object Name
    $TotalCards = foreach ($Group in $Totals) {
        $Class = ([string]$Group.Name).ToLowerInvariant()
        "<div class='metric'><strong>$($Group.Count)</strong><span class='status $Class'>$($Group.Name)</span></div>"
    }

@"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M365 Tenant Baseline Audit</title>
  <style>
    :root { --bg:#0f172a; --card:#111827; --text:#e5e7eb; --muted:#9ca3af; --line:#334155; --pass:#22c55e; --info:#38bdf8; --warn:#f59e0b; --fail:#ef4444; --skip:#94a3b8; }
    body { margin:0; font-family:Segoe UI,Arial,sans-serif; background:#020617; color:var(--text); }
    header, main { max-width:1180px; margin:0 auto; padding:28px; }
    header { padding-top:42px; }
    h1 { margin:0 0 8px; font-size:34px; }
    p { color:var(--muted); line-height:1.55; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:24px 0; }
    .metric, .card { background:linear-gradient(180deg,#111827,#0b1120); border:1px solid var(--line); border-radius:14px; padding:18px; }
    .metric strong { display:block; font-size:30px; }
    table { width:100%; border-collapse:collapse; background:#0b1120; border:1px solid var(--line); border-radius:14px; overflow:hidden; }
    th, td { text-align:left; padding:11px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
    th { background:#111827; color:#f8fafc; }
    .status { display:inline-block; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:700; }
    .pass { background:rgba(34,197,94,.15); color:var(--pass); }
    .info { background:rgba(56,189,248,.15); color:var(--info); }
    .warn { background:rgba(245,158,11,.15); color:var(--warn); }
    .fail { background:rgba(239,68,68,.15); color:var(--fail); }
    .skipped { background:rgba(148,163,184,.15); color:var(--skip); }
    footer { color:var(--muted); border-top:1px solid var(--line); margin-top:30px; padding-top:18px; }
  </style>
</head>
<body>
  <header>
    <h1>M365 Tenant Baseline Audit</h1>
    <p>Generated $([System.Net.WebUtility]::HtmlEncode($GeneratedAt)). Privacy mode: $([System.Net.WebUtility]::HtmlEncode($PrivacyMode)). Read-only audit output.</p>
    <div class="grid">
      $($TotalCards -join "`n")
    </div>
  </header>
  <main>
    <section class="card">
      <h2>Findings</h2>
      <table>
        <thead><tr><th>Area</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>
          $($Rows -join "`n")
        </tbody>
      </table>
    </section>
    <footer>
      M365 Tenant Baseline Audit. Read-only. Public-safe by design. Review generated reports before sharing.
    </footer>
  </main>
</body>
</html>
"@
}

if (-not (Test-CommandAvailable -Name "Invoke-MgGraphRequest")) {
    throw "Microsoft Graph PowerShell SDK is required. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
}

if (-not $SkipGraphConnect) {
    $GraphConnectParameters = @{
        Scopes       = $Scopes
        NoWelcome    = $true
        ContextScope = "Process"
    }

    if ($TenantId) {
        $GraphConnectParameters["TenantId"] = $TenantId
    }

    if ($ClientId) {
        $GraphConnectParameters["ClientId"] = $ClientId
    }

    Connect-MgGraph @GraphConnectParameters
}

$GraphContextValidation = Assert-ReadOnlyGraphContext -ExpectedReadOnlyScopes $Scopes

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutDir = Join-Path $OutputPath "m365-tenant-baseline-audit-$Timestamp"
New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

$Findings = [System.Collections.Generic.List[object]]::new()
$Data = [ordered]@{
    GeneratedAt = (Get-Date).ToString("s")
    PrivacyMode = $PrivacyMode
    GraphScopes = @($GraphContextValidation.Scopes)
    GraphContext = @{
        Account = ConvertTo-SafeText $GraphContextValidation.Account
        TenantId = ConvertTo-SafeText $GraphContextValidation.TenantId
        ContextScope = [string]$GraphContextValidation.ContextScope
        UnexpectedScopes = @($GraphContextValidation.UnexpectedScopes)
    }
    Tenant = @{}
    Identity = @{}
    Intune = @{}
    ExchangeOnline = @{}
}

Write-Host "Collecting Microsoft 365 tenant baseline..." -ForegroundColor Cyan

$Findings.Add((New-Finding -Area "Safety" -Check "Microsoft Graph context" -Status "PASS" -Detail "Read-only scope validation passed. Context scope: $($GraphContextValidation.ContextScope)."))
if (@($GraphContextValidation.UnexpectedScopes).Count -gt 0) {
    $Findings.Add((New-Finding -Area "Safety" -Check "Unexpected non-write scopes" -Status "INFO" -Detail (ConvertTo-SafeText "Additional non-write scopes present: $($GraphContextValidation.UnexpectedScopes -join ', ')")))
}

$Organization = Invoke-GraphGet -Uri "/v1.0/organization" -Area "Tenant" -Name "Organization"
if ($Organization.__Skipped) {
    $Findings.Add((New-Finding -Area "Tenant" -Check "Organization" -Status "SKIPPED" -Detail (ConvertTo-SafeText $Organization.Error)))
}
else {
    $Org = @($Organization.value | Select-Object -First 1)
    $Data.Tenant.Organization = $Org
    $SyncText = if ($null -ne $Org.onPremisesSyncEnabled) { "On-premises sync flag: $($Org.onPremisesSyncEnabled)" } else { "On-premises sync flag not returned" }
    $Findings.Add((New-Finding -Area "Tenant" -Check "Organization readable" -Status "PASS" -Detail (ConvertTo-SafeText "Tenant organization data readable. $SyncText")))
}

$Domains = Invoke-GraphGet -Uri "/v1.0/domains" -Area "Tenant" -Name "Domains"
if ($Domains.__Skipped) {
    $Findings.Add((New-Finding -Area "Tenant" -Check "Domains" -Status "SKIPPED" -Detail (ConvertTo-SafeText $Domains.Error)))
}
else {
    $DomainCount = @($Domains.value).Count
    $DefaultDomain = @($Domains.value | Where-Object { $_.isDefault } | Select-Object -First 1).id
    $Data.Tenant.Domains = $Domains.value
    $Findings.Add((New-Finding -Area "Tenant" -Check "Verified domains" -Status "PASS" -Detail (ConvertTo-SafeText "$DomainCount domain(s). Default: $DefaultDomain")))
}

$Skus = Invoke-GraphGet -Uri "/v1.0/subscribedSkus" -Area "Tenant" -Name "Licensing"
if ($Skus.__Skipped) {
    $Findings.Add((New-Finding -Area "Tenant" -Check "Licensing" -Status "SKIPPED" -Detail (ConvertTo-SafeText $Skus.Error)))
}
else {
    $SkuCount = @($Skus.value).Count
    $Data.Tenant.Skus = $Skus.value
    $Findings.Add((New-Finding -Area "Tenant" -Check "Subscribed SKUs" -Status "PASS" -Detail "$SkuCount subscribed SKU object(s) readable."))
}

$UserCount = Get-GraphCollectionCount -Uri "/v1.0/users/`$count" -Area "Identity" -Name "Users"
if ($UserCount.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Users" -Status "SKIPPED" -Detail (ConvertTo-SafeText $UserCount.Error))) }
else { $Data.Identity.Users = @{ Count = $UserCount }; $Findings.Add((New-Finding -Area "Identity" -Check "Users" -Status "PASS" -Detail "$UserCount user object(s).")) }

$GuestCount = Get-GraphCollectionCount -Uri "/v1.0/users/`$count?`$filter=userType eq 'Guest'" -Area "Identity" -Name "Guest users"
if ($GuestCount.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Guest users" -Status "SKIPPED" -Detail (ConvertTo-SafeText $GuestCount.Error))) }
else { $Data.Identity.Guests = @{ Count = $GuestCount }; $Findings.Add((New-Finding -Area "Identity" -Check "Guest users" -Status "INFO" -Detail "$GuestCount guest user object(s).")) }

$GroupCount = Get-GraphCollectionCount -Uri "/v1.0/groups/`$count" -Area "Identity" -Name "Groups"
if ($GroupCount.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Groups" -Status "SKIPPED" -Detail (ConvertTo-SafeText $GroupCount.Error))) }
else { $Data.Identity.Groups = @{ Count = $GroupCount }; $Findings.Add((New-Finding -Area "Identity" -Check "Groups" -Status "PASS" -Detail "$GroupCount group object(s).")) }

$DeviceCount = Get-GraphCollectionCount -Uri "/v1.0/devices/`$count" -Area "Identity" -Name "Devices"
if ($DeviceCount.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Devices" -Status "SKIPPED" -Detail (ConvertTo-SafeText $DeviceCount.Error))) }
else { $Data.Identity.Devices = @{ Count = $DeviceCount }; $Findings.Add((New-Finding -Area "Identity" -Check "Devices" -Status "PASS" -Detail "$DeviceCount Entra device object(s).")) }

$DirectoryRoles = Invoke-GraphGet -Uri "/v1.0/directoryRoles" -Area "Identity" -Name "Directory roles"
if ($DirectoryRoles.__Skipped) {
    $Findings.Add((New-Finding -Area "Identity" -Check "Directory roles" -Status "SKIPPED" -Detail (ConvertTo-SafeText $DirectoryRoles.Error)))
}
else {
    $RoleSummary = foreach ($Role in @($DirectoryRoles.value)) {
        $MemberResult = Invoke-GraphGet -Uri "/v1.0/directoryRoles/$($Role.id)/members" -Area "Identity" -Name "Role members"
        [pscustomobject]@{
            DisplayName = $Role.displayName
            MemberCount = if ($MemberResult.__Skipped) { $null } else { @($MemberResult.value).Count }
        }
    }

    $Data.Identity.DirectoryRoles = $RoleSummary
    $PrivilegedCount = @($RoleSummary | Where-Object { $_.MemberCount -gt 0 }).Count
    $Findings.Add((New-Finding -Area "Identity" -Check "Privileged role inventory" -Status "INFO" -Detail "$($RoleSummary.Count) activated directory role(s), $PrivilegedCount with one or more member(s)."))
}

$CAPolicies = Invoke-GraphGet -Uri "/v1.0/identity/conditionalAccess/policies" -Area "Identity" -Name "Conditional Access"
if ($CAPolicies.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Conditional Access policies" -Status "SKIPPED" -Detail (ConvertTo-SafeText $CAPolicies.Error))) }
else {
    $Policies = @($CAPolicies.value)
    $Enabled = @($Policies | Where-Object { $_.state -eq "enabled" }).Count
    $ReportOnly = @($Policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
    $Disabled = @($Policies | Where-Object { $_.state -eq "disabled" }).Count
    $Data.Identity.ConditionalAccess = @{ Total = $Policies.Count; Enabled = $Enabled; ReportOnly = $ReportOnly; Disabled = $Disabled }
    $Status = if ($Policies.Count -gt 0) { "PASS" } else { "WARN" }
    $Findings.Add((New-Finding -Area "Identity" -Check "Conditional Access policies" -Status $Status -Detail "$($Policies.Count) policie(s): $Enabled enabled, $ReportOnly report-only, $Disabled disabled."))
}

$NamedLocations = Invoke-GraphGet -Uri "/v1.0/identity/conditionalAccess/namedLocations" -Area "Identity" -Name "Named locations"
if ($NamedLocations.__Skipped) { $Findings.Add((New-Finding -Area "Identity" -Check "Named locations" -Status "SKIPPED" -Detail (ConvertTo-SafeText $NamedLocations.Error))) }
else { $Findings.Add((New-Finding -Area "Identity" -Check "Named locations" -Status "INFO" -Detail "$(@($NamedLocations.value).Count) named location object(s).")) }

$AuthMethodsPolicy = Invoke-GraphGet -Uri "/v1.0/policies/authenticationMethodsPolicy" -Area "Identity" -Name "Authentication methods policy"
Add-SectionStatus -Findings $Findings -Area "Identity" -Check "Authentication methods policy" -Value $AuthMethodsPolicy -SuccessDetail "Authentication methods policy readable."

$AppCount = Get-GraphCollectionCount -Uri "/v1.0/applications/`$count" -Area "Applications" -Name "App registrations"
if ($AppCount.__Skipped) { $Findings.Add((New-Finding -Area "Applications" -Check "App registrations" -Status "SKIPPED" -Detail (ConvertTo-SafeText $AppCount.Error))) }
else { $Findings.Add((New-Finding -Area "Applications" -Check "App registrations" -Status "INFO" -Detail "$AppCount application registration object(s).")) }

$SpCount = Get-GraphCollectionCount -Uri "/v1.0/servicePrincipals/`$count" -Area "Applications" -Name "Enterprise applications"
if ($SpCount.__Skipped) { $Findings.Add((New-Finding -Area "Applications" -Check "Enterprise applications" -Status "SKIPPED" -Detail (ConvertTo-SafeText $SpCount.Error))) }
else { $Findings.Add((New-Finding -Area "Applications" -Check "Enterprise applications" -Status "INFO" -Detail "$SpCount service principal object(s).")) }

$ManagedDeviceCount = Get-GraphCollectionCount -Uri "/v1.0/deviceManagement/managedDevices/`$count" -Area "Intune" -Name "Managed devices"
if ($ManagedDeviceCount.__Skipped) { $Findings.Add((New-Finding -Area "Intune" -Check "Managed devices" -Status "SKIPPED" -Detail (ConvertTo-SafeText $ManagedDeviceCount.Error))) }
else { $Data.Intune.ManagedDevices = @{ Count = $ManagedDeviceCount }; $Findings.Add((New-Finding -Area "Intune" -Check "Managed devices" -Status "PASS" -Detail "$ManagedDeviceCount managed device object(s).")) }

$CompliancePolicies = Invoke-GraphGet -Uri "/v1.0/deviceManagement/deviceCompliancePolicies" -Area "Intune" -Name "Compliance policies"
if ($CompliancePolicies.__Skipped) { $Findings.Add((New-Finding -Area "Intune" -Check "Compliance policies" -Status "SKIPPED" -Detail (ConvertTo-SafeText $CompliancePolicies.Error))) }
else { $Findings.Add((New-Finding -Area "Intune" -Check "Compliance policies" -Status "INFO" -Detail "$(@($CompliancePolicies.value).Count) compliance policie(s).")) }

$ConfigurationProfiles = Invoke-GraphGet -Uri "/v1.0/deviceManagement/deviceConfigurations" -Area "Intune" -Name "Configuration profiles"
if ($ConfigurationProfiles.__Skipped) { $Findings.Add((New-Finding -Area "Intune" -Check "Configuration profiles" -Status "SKIPPED" -Detail (ConvertTo-SafeText $ConfigurationProfiles.Error))) }
else { $Findings.Add((New-Finding -Area "Intune" -Check "Configuration profiles" -Status "INFO" -Detail "$(@($ConfigurationProfiles.value).Count) configuration profile(s).")) }

$MobileApps = Invoke-GraphGet -Uri "/v1.0/deviceAppManagement/mobileApps" -Area "Intune" -Name "Mobile apps"
if ($MobileApps.__Skipped) { $Findings.Add((New-Finding -Area "Intune" -Check "Mobile apps" -Status "SKIPPED" -Detail (ConvertTo-SafeText $MobileApps.Error))) }
else { $Findings.Add((New-Finding -Area "Intune" -Check "Mobile apps" -Status "INFO" -Detail "$(@($MobileApps.value).Count) mobile app object(s).")) }

if ($IncludeExchangeOnline) {
    if (-not (Test-CommandAvailable -Name "Connect-ExchangeOnline")) {
        $Findings.Add((New-Finding -Area "Exchange Online" -Check "Module" -Status "SKIPPED" -Detail "ExchangeOnlineManagement module not available."))
    }
    else {
        try {
            $Commands = @("Get-AcceptedDomain", "Get-EXOMailbox", "Get-TransportRule")
            Connect-ExchangeOnline -ShowBanner:$false -CommandName $Commands

            $AcceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
            $Mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -Properties RecipientTypeDetails,ForwardingSmtpAddress,DeliverToMailboxAndForward -ErrorAction Stop)
            $TransportRules = @(Get-TransportRule -ErrorAction SilentlyContinue)

            $SharedMailboxCount = @($Mailboxes | Where-Object { $_.RecipientTypeDetails -eq "SharedMailbox" }).Count
            $ForwardingCount = @($Mailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.DeliverToMailboxAndForward }).Count

            $Data.ExchangeOnline = @{
                AcceptedDomains = $AcceptedDomains.Count
                Mailboxes = $Mailboxes.Count
                SharedMailboxes = $SharedMailboxCount
                TransportRules = $TransportRules.Count
                ForwardingIndicators = $ForwardingCount
            }

            $Findings.Add((New-Finding -Area "Exchange Online" -Check "Accepted domains" -Status "PASS" -Detail "$($AcceptedDomains.Count) accepted domain(s)."))
            $Findings.Add((New-Finding -Area "Exchange Online" -Check "Mailboxes" -Status "INFO" -Detail "$($Mailboxes.Count) mailbox object(s), $SharedMailboxCount shared mailbox object(s)."))
            $Findings.Add((New-Finding -Area "Exchange Online" -Check "Forwarding indicators" -Status "INFO" -Detail "$ForwardingCount mailbox object(s) with forwarding indicators readable."))
            $Findings.Add((New-Finding -Area "Exchange Online" -Check "Transport rules" -Status "INFO" -Detail "$($TransportRules.Count) transport rule(s)."))
        }
        catch {
            $Findings.Add((New-Finding -Area "Exchange Online" -Check "Optional collection" -Status "SKIPPED" -Detail (ConvertTo-SafeText $_.Exception.Message)))
        }
        finally {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
else {
    $Findings.Add((New-Finding -Area "Exchange Online" -Check "Optional collection" -Status "SKIPPED" -Detail "Use -IncludeExchangeOnline to collect read-only Exchange Online baseline."))
}

$Data.Findings = $Findings

$FindingRows = foreach ($Finding in $Findings) {
    [pscustomobject]@{
        Area   = $Finding.Area
        Check  = $Finding.Check
        Status = $Finding.Status
        Detail = ConvertTo-SafeText $Finding.Detail
    }
}

$CsvPath = Join-Path $OutDir "m365-tenant-baseline-findings.csv"
$JsonPath = Join-Path $OutDir "m365-tenant-baseline-data.json"
$HtmlPath = Join-Path $OutDir "m365-tenant-baseline-summary.html"
$TxtPath = Join-Path $OutDir "m365-tenant-baseline-summary.txt"

$FindingRows | Sort-Object Area, Check | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
$Data | ConvertTo-Json -Depth 20 | Set-Content -Path $JsonPath -Encoding UTF8
$FindingRows | Sort-Object Area, Check | Format-Table -AutoSize | Out-String | Set-Content -Path $TxtPath -Encoding UTF8
$Html = New-HtmlReport -Findings $FindingRows -Data $Data -GeneratedAt (Get-Date).ToString("s")
$Html | Set-Content -Path $HtmlPath -Encoding UTF8

Write-Host "Audit completed." -ForegroundColor Green
Write-Host "Output folder: $OutDir" -ForegroundColor Cyan
Write-Host "CSV:  $CsvPath" -ForegroundColor Cyan
Write-Host "HTML: $HtmlPath" -ForegroundColor Cyan
Write-Host "TXT:  $TxtPath" -ForegroundColor Cyan
Write-Host "JSON: $JsonPath" -ForegroundColor Cyan
