param(
    [string]$Output = "dist\WinTraceLens-legacy.exe",
    [string]$Version = "1.2.0-legacy"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot "cmd\wintracelenslegacy\app.manifest"
$icon = Join-Path $repoRoot "assets\wintracelens.ico"
$resource = Join-Path $repoRoot "cmd\wintracelenslegacy\rsrc_windows_amd64.syso"
$outputPath = Join-Path $repoRoot $Output

Push-Location $repoRoot
try {
    $goVersion = (& go1.20.14 version 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $goVersion -notmatch "go1\.20\.14") {
        throw "Legacy build requires go1.20.14. Actual output: $goVersion"
    }
    Write-Host $goVersion

    & go1.20.14 run .\tools\icon-gen -output $icon
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $icon)) {
        throw "Application icon generation failed."
    }

    & go1.20.14 run github.com/akavel/rsrc@v0.10.2 -arch amd64 -manifest $manifest -ico $icon -o $resource
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $resource)) {
        throw "Windows resource generation failed."
    }

    $testPackages = @(& go1.20.14 list ./... | Where-Object {
        $_ -notmatch '/internal/(server|investigation)$'
    })
    if ($LASTEXITCODE -ne 0 -or $testPackages.Count -eq 0) {
        throw "Unable to resolve Legacy test packages."
    }
    & go1.20.14 test $testPackages
    if ($LASTEXITCODE -ne 0) {
        throw "Legacy tests failed."
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $outputPath) -Force | Out-Null
    & go1.20.14 build -trimpath -ldflags "-H=windowsgui -s -w -X main.version=$Version" -o $outputPath .\cmd\wintracelenslegacy
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputPath)) {
        throw "Legacy release build failed."
    }

    $stream = [IO.File]::OpenRead($outputPath)
    try {
        $reader = [IO.BinaryReader]::new($stream)
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset + 24 + 68
        $subsystem = $reader.ReadUInt16()
        if ($subsystem -ne 2) {
            throw "Legacy release is not a Windows GUI executable. PE subsystem: $subsystem"
        }
    } finally {
        $stream.Dispose()
    }

    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $outputPath).Hash
    $checksumPath = "${outputPath}.sha256.txt"
    $checksumLine = "$hash  $([IO.Path]::GetFileName($outputPath))"
    $checksumLine | Set-Content -LiteralPath $checksumPath -Encoding ASCII
    $checksumLine | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $outputPath) "SHA256SUMS.txt") -Encoding ASCII
    Write-Host "Legacy executable: $outputPath"
    Write-Host "SHA-256: $hash"
} finally {
    Pop-Location
}
