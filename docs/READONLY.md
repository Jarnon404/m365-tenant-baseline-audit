# Read-only assurance

This project is designed for read-only Microsoft 365 tenant baseline auditing.

## Enforcement layers

The script uses three layers:

1. Operator model: Global Reader or equivalent read-only access.
2. Permission model: delegated Microsoft Graph read scopes only.
3. Code model: Microsoft Graph `GET` requests and optional Exchange Online `Get-*` cmdlets only.

## Microsoft Graph context guard

Before audit collection starts, the script checks the active Graph context. If the session contains write-capable or broad scopes, the script stops.

Blocked scope indicators include:

- `Write`
- `ReadWrite`
- `FullControl`
- `AccessAsUser`
- `RoleManagement.ReadWrite`
- `Policy.ReadWrite`

This is intentional. A tenant may have broad delegated permissions consented for the default Microsoft Graph PowerShell enterprise application, even when a user asks for read-only scopes at connection time. The script should not run under that context.

## Recommended app model

Use a dedicated Entra ID app registration for this audit with only read-only delegated permissions.

Example:

```powershell
.\scripts\Invoke-M365TenantBaselineAudit.ps1 `
  -TenantId "<TENANT_ID>" `
  -ClientId "<READ_ONLY_APP_CLIENT_ID>" `
  -OutputPath C:\Temp\M365TenantBaselineAudit
```

## Local writes

The only writes performed by the script are local report files under the selected output folder.

Generated files:

- `m365-tenant-baseline-summary.html`
- `m365-tenant-baseline-findings.csv`
- `m365-tenant-baseline-summary.txt`
- `m365-tenant-baseline-data.json`

## Optional Exchange Online

The optional Exchange Online section imports and uses only read-only commands:

- `Get-AcceptedDomain`
- `Get-EXOMailbox`
- `Get-TransportRule`
