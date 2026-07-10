$ErrorActionPreference = "Stop"

BeforeAll {
    $script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

Describe "Repository structure" {
    It "Has a README" {
        Test-Path (Join-Path $script:RepositoryRoot "README.md") | Should -BeTrue
    }

    It "Has a LICENSE file" {
        Test-Path (Join-Path $script:RepositoryRoot "LICENSE") | Should -BeTrue
    }

    It "Has documentation folder" {
        Test-Path (Join-Path $script:RepositoryRoot "docs") | Should -BeTrue
    }

    It "Has script folder" {
        Test-Path (Join-Path $script:RepositoryRoot "scripts") | Should -BeTrue
    }
}

Describe "PowerShell scripts" {
    It "Contains at least one PowerShell script" {
        $ScriptFiles = Get-ChildItem -Path (Join-Path $script:RepositoryRoot "scripts") -Filter "*.ps1" -Recurse -File
        $ScriptFiles.Count | Should -BeGreaterThan 0
    }

    It "PowerShell scripts parse successfully" {
        $ScriptFiles = Get-ChildItem -Path (Join-Path $script:RepositoryRoot "scripts") -Filter "*.ps1" -Recurse -File

        foreach ($ScriptFile in $ScriptFiles) {
            $Errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptFile.FullName -Raw), [ref]$Errors)
            $Errors | Should -BeNullOrEmpty
        }
    }
}

Describe "Repository metadata" {
    It "Has VERSION.txt" {
        Test-Path (Join-Path $script:RepositoryRoot "VERSION.txt") | Should -BeTrue
    }

    It "Has CHECKSUMS.sha256" {
        Test-Path (Join-Path $script:RepositoryRoot "CHECKSUMS.sha256") | Should -BeTrue
    }

    It "Has SECURITY.md" {
        Test-Path (Join-Path $script:RepositoryRoot "SECURITY.md") | Should -BeTrue
    }
}

Describe "Public safety" {
    It "Does not contain obvious tenant-specific placeholders from private environments" {
        $ForbiddenPatterns = @(
            "real-tenant-id",
            "customer.local",
            "corp.local",
            "tenant.onmicrosoft.com",
            "password=",
            "client_secret"
        )

        $Files = Get-ChildItem -Path $script:RepositoryRoot -Recurse -File |
            Where-Object {
                $_.FullName -notmatch "[\\/]\.git[\\/]" -and
                $_.Extension -in @(".ps1", ".md", ".json", ".yml", ".yaml", ".html", ".txt", "")
            }

        $Hits = foreach ($File in $Files) {
            $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue
            foreach ($Pattern in $ForbiddenPatterns) {
                if ($Content -match [regex]::Escape($Pattern)) {
                    "$($File.FullName): $Pattern"
                }
            }
        }

        $Hits | Should -BeNullOrEmpty
    }
}


Describe "Read-only enforcement" {
    BeforeAll {
        $script:AuditScriptPath = Join-Path $script:RepositoryRoot "scripts/Invoke-M365TenantBaselineAudit.ps1"
        $script:AuditScriptContent = Get-Content $script:AuditScriptPath -Raw
    }

    It "Contains a Microsoft Graph read-only scope guard" {
        $script:AuditScriptContent | Should -Match "function Assert-ReadOnlyGraphContext"
        $script:AuditScriptContent | Should -Match "Unsafe Microsoft Graph context detected"
    }

    It "Uses Microsoft Graph GET requests only" {
        $script:AuditScriptContent | Should -Match "Invoke-MgGraphRequest -Method GET"
        $script:AuditScriptContent | Should -Not -Match "Invoke-MgGraphRequest\s+-Method\s+(POST|PUT|PATCH|DELETE)"
    }

    It "Does not contain Microsoft Graph tenant mutation cmdlets" {
        $script:AuditScriptContent | Should -Not -Match "\b(New|Set|Update|Remove)-Mg[A-Za-z]"
    }

    It "Uses process-scoped Microsoft Graph context" {
        $script:AuditScriptContent | Should -Match "ContextScope\s*=\s*\"Process\""
    }

    It "Limits optional Exchange Online collection to read-only commands" {
        $script:AuditScriptContent | Should -Match '"Get-AcceptedDomain"'
        $script:AuditScriptContent | Should -Match '"Get-EXOMailbox"'
        $script:AuditScriptContent | Should -Match '"Get-TransportRule"'
        $script:AuditScriptContent | Should -Not -Match "\b(Set|New|Remove)-(AcceptedDomain|EXOMailbox|TransportRule|Mailbox|OrganizationConfig|DistributionGroup)"
    }
}
