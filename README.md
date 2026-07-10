# M365 Tenant Baseline Audit

Public-safe, read-only PowerShell toolkit for auditing Microsoft 365 tenant baseline posture with Global Reader style access.

[![PSScriptAnalyzer](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/psscriptanalyzer.yml)
[![Pester Tests](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/pester.yml/badge.svg)](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/pester.yml)
[![Secret Scan](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/gitleaks.yml)
[![Public Safety Check](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/public-safety-check.yml/badge.svg)](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/public-safety-check.yml)
[![GitHub Pages](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/pages.yml/badge.svg)](https://github.com/Jarnon404/m365-tenant-baseline-audit/actions/workflows/pages.yml)
[![Release](https://img.shields.io/github/v/release/Jarnon404/m365-tenant-baseline-audit)](https://github.com/Jarnon404/m365-tenant-baseline-audit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Purpose

This repository provides a read-only baseline audit script for Microsoft 365 tenants. It is intended for IT specialists who need a practical overview of tenant readiness, identity posture, endpoint visibility, Exchange Online basics and repository-safe reporting.

The toolkit follows the same policy as the other Jarnon404 audit repositories:

- read-only by design
- no remediation actions
- no tenant-specific data committed to the repository
- public-safe examples only
- HTML, CSV, TXT and JSON outputs
- GitHub Actions validation

## Access model

The intended operator role is **Global Reader**.

The script uses delegated Microsoft Graph PowerShell access and read-only Graph scopes. Some sections may be skipped if the signed-in user or tenant consent does not allow a specific API. This is intentional: the report should complete with clear `SKIPPED` or `INFO` findings instead of requiring Global Administrator.

The script enforces a read-only Microsoft Graph context before collection starts. If the active Graph session contains write-capable or broad scopes such as `ReadWrite`, `Write`, `FullControl`, `Directory.AccessAsUser.All`, `Policy.ReadWrite.*` or `RoleManagement.ReadWrite.*`, the audit stops before collecting data.

Optional Exchange Online collection can be enabled with `-IncludeExchangeOnline`. It imports only a limited command set and uses read-only `Get-*` cmdlets.


## Read-only enforcement

This repository treats read-only as a technical requirement, not a marketing sentence that wandered into a README and hoped nobody would notice.

The audit script checks the active Microsoft Graph context using `Get-MgContext` after connecting. The run stops if the context contains write-capable delegated scopes. This protects against tenants where the default **Microsoft Graph Command Line Tools** enterprise application has previously been granted broad permissions.

The safest model is to use a dedicated Entra ID app registration for this audit with only the required read-only delegated permissions.

Recommended connection model:

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -TenantId "<TENANT_ID>" `
  -ClientId "<READ_ONLY_APP_CLIENT_ID>" `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

If a Graph context contains unsafe scopes, the script stops before any audit collection starts.

## What it checks

### Tenant and licensing

- Tenant ID and display name
- Verified domains
- Default and initial domain visibility
- On-premises synchronization flag where available
- Subscribed SKU summary

### Identity baseline

- User, guest, group and device counts
- Directory role inventory
- Privileged role membership counts
- Conditional Access policy inventory
- Named locations
- Authentication methods policy visibility
- Application registrations and enterprise applications summary

### Endpoint and Intune visibility

- Managed device count
- Compliance policy count
- Configuration profile count
- Mobile app count
- App protection policy visibility where available

### Exchange Online optional baseline

- Accepted domain count
- Mailbox and shared mailbox summary
- Transport rule count
- Mail forwarding indicators where readable

## Usage

Install Microsoft Graph PowerShell if needed:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Run the read-only audit with the default Microsoft Graph PowerShell application:

```powershell
cd C:\GitHub\m365-tenant-baseline-audit

.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

Recommended run with a dedicated read-only app registration:

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -TenantId "<TENANT_ID>" `
  -ClientId "<READ_ONLY_APP_CLIENT_ID>" `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

Run with optional Exchange Online collection:

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -OutputPath C:\Temp\M365TenantBaselineAudit `
  -IncludeExchangeOnline
```

Use explicit scopes if your tenant requires them:

```powershell
$Scopes = @(
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
)

.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -Scopes $Scopes `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

## Output

The script creates a timestamped folder containing:

- `m365-tenant-baseline-summary.html`
- `m365-tenant-baseline-findings.csv`
- `m365-tenant-baseline-summary.txt`
- `m365-tenant-baseline-data.json`

## Privacy modes

Default privacy mode is `Sanitized`. It masks common tenant identifiers in report details.

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 -PrivacyMode Sanitized
```

For internal-only reports, use:

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 -PrivacyMode Full
```

Do not commit generated reports unless they are reviewed and sanitized.

## Tenant safety summary

The script is designed to:

- use Microsoft Graph `GET` requests only
- use read-only Microsoft Graph scopes
- stop if the active Graph context contains write-capable scopes
- use only Exchange Online `Get-*` cmdlets when optional Exchange collection is enabled
- write output only to the local report folder

It does not create, update, remove, enable, disable or modify Microsoft 365 tenant configuration.

## Repository status

This repository is designed as a public-safe portfolio project. It demonstrates Microsoft 365 tenant baseline audit thinking, read-only collection design, Graph PowerShell usage, HTML reporting, GitHub Actions validation and documentation discipline.

## License

MIT License. See [LICENSE](LICENSE).
