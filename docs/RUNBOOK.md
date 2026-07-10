# Runbook

## Prerequisites

- PowerShell 7 recommended
- Microsoft.Graph PowerShell module
- Global Reader role or equivalent read-only access
- Tenant consent for requested delegated Graph scopes

## Basic run

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser

.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

## Recommended read-only app run

Use a dedicated Entra ID app registration with only read-only delegated Microsoft Graph permissions.

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -TenantId "<TENANT_ID>" `
  -ClientId "<READ_ONLY_APP_CLIENT_ID>" `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

The script validates the Graph context and stops if write-capable scopes are present.

## Optional Exchange Online run

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser

.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -OutputPath C:\Temp\M365TenantBaselineAudit `
  -IncludeExchangeOnline
```

## Expected behavior

The script should complete even when some Graph areas are unavailable. Those sections are marked as `SKIPPED` with the read failure detail.
