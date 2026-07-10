# Changelog

## v1.0.0 - Initial public-safe release

### Read-only scope guard
- Added mandatory Microsoft Graph context validation before collection starts.
- The audit stops when write-capable scopes such as ReadWrite, Write, FullControl or AccessAsUser are present.
- Added documentation recommending a dedicated read-only app registration for this audit.

### Added
- Read-only Microsoft 365 tenant baseline audit script.
- Microsoft Graph delegated access model for Global Reader style audits.
- Optional Exchange Online read-only collection mode.
- HTML, CSV, TXT and JSON report output.
- Sanitized privacy mode.
- GitHub Actions validation, Pester tests, PSScriptAnalyzer, secret scan and public-safety check.
