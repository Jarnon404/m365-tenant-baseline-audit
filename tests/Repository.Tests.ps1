$ErrorActionPreference = "Stop"

BeforeAll {
    $script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    $script:MainScriptPath = Join-Path $script:RepositoryRoot "scripts/Invoke-M365TenantBaselineAudit.ps1"
    $script:MainScript = Get-Content $script:MainScriptPath -Raw
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
        $ScriptFiles = Get-ChildItem `
            -Path (Join-Path $script:RepositoryRoot "scripts") `
            -Filter "*.ps1" `
            -Recurse `
            -File

        $ScriptFiles.Count | Should -BeGreaterThan 0
    }

    It "PowerShell scripts parse successfully" {
        $ScriptFiles = Get-ChildItem `
            -Path (Join-Path $script:RepositoryRoot "scripts") `
            -Filter "*.ps1" `
            -Recurse `
            -File

        foreach ($ScriptFile in $ScriptFiles) {
            $Errors = $null

            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content $ScriptFile.FullName -Raw),
                [ref]$Errors
            )

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
        $Patterns = @(
            ("real" + "-tenant-id"),
            ("customer" + ".local"),
            ("corp" + ".local"),
            ("tenant" + ".onmicrosoft.com"),
            ("password" + "="),
            ("client" + "_secret")
        )

        $ExcludedRelativePaths = @(
            ".github/workflows/public-safety-check.yml",
            "tests/Repository.Tests.ps1"
        )

        $Files = Get-ChildItem -Path $script:RepositoryRoot -Recurse -File |
            Where-Object {
                $RelativePath = $_.FullName.Replace($script:RepositoryRoot, "").TrimStart("\","/").Replace("\","/")

                $_.FullName -notmatch "\\.git\\" -and
                $_.Extension -in @(".ps1", ".md", ".json", ".yml", ".yaml", ".html", ".txt", "") -and
                $RelativePath -notin $ExcludedRelativePaths
            }

        $Hits = foreach ($File in $Files) {
            $Content = Get-Content $File.FullName -Raw -ErrorAction SilentlyContinue

            foreach ($Pattern in $Patterns) {
                if ($Content -match [regex]::Escape($Pattern)) {
                    "$($File.FullName): $Pattern"
                }
            }
        }

        $Hits | Should -BeNullOrEmpty
    }
}

Describe "Read-only enforcement" {
    It "Contains a Microsoft Graph read-only scope guard" {
        $script:MainScript | Should -Match "Assert-ReadOnlyGraphContext"
    }

    It "Uses Microsoft Graph GET requests only" {
        $script:MainScript | Should -Match 'Invoke-MgGraphRequest\s+-Method\s+GET'
        $script:MainScript | Should -Not -Match 'Invoke-MgGraphRequest\s+-Method\s+(POST|PUT|PATCH|DELETE)'
    }

    It "Does not contain Microsoft Graph tenant mutation cmdlets" {
        $script:MainScript | Should -Not -Match '\b(New|Set|Update|Remove)-Mg'
    }

    It "Uses process-scoped Microsoft Graph context" {
        $script:MainScript | Should -Match ([regex]::Escape('ContextScope = "Process"'))
    }

    It "Limits optional Exchange Online collection to read-only commands" {
        $script:MainScript | Should -Match "Get-AcceptedDomain"
        $script:MainScript | Should -Match "Get-EXOMailbox"
        $script:MainScript | Should -Match "Get-TransportRule"

        $script:MainScript | Should -Not -Match '\b(New|Set|Remove)-TransportRule\b'
        $script:MainScript | Should -Not -Match '\b(Set|New|Remove)-Mailbox\b'
        $script:MainScript | Should -Not -Match '\bSet-OrganizationConfig\b'
    }
}

