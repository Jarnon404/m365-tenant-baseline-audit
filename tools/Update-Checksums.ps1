$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
$Output = Join-Path $Root "CHECKSUMS.sha256"

$Files = Get-ChildItem -Path $Root -Recurse -File |
    Where-Object {
        $_.FullName -notmatch "[\\/]\.git[\\/]" -and
        $_.Name -ne "CHECKSUMS.sha256"
    } |
    Sort-Object FullName

$Lines = foreach ($File in $Files) {
    $Hash = Get-FileHash -Algorithm SHA256 -Path $File.FullName
    $Relative = $File.FullName.Replace($Root.Path, "").TrimStart("\", "/").Replace("\", "/")
    "$($Hash.Hash.ToLowerInvariant())  $Relative"
}

$Lines | Set-Content -Path $Output -Encoding UTF8
Write-Host "CHECKSUMS.sha256 refreshed."
