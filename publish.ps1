<#
.SYNOPSIS
    Builds a distributable Tapo Viewer.

.DESCRIPTION
    Publishes the UI and the sandboxed decoder into one self-contained folder:

        artifacts\TapoViewer\
            TapoViewer.App.exe        <- run this
            decoder\
                TapoViewer.Decoder.exe

    The decoder is published separately into its own subdirectory rather than being merged in.
    Two reasons. It is launched as a process and never loaded into the UI — keeping the payloads
    apart makes that boundary visible on disk. And libVLC needs its plugins\ tree present as real
    files, so it cannot be folded into a single-file bundle.

.PARAMETER FrameworkDependent
    Produce a much smaller build that requires the .NET 8 Desktop Runtime to be installed.
    The default is self-contained: larger, but runs on a machine with no .NET at all.

.EXAMPLE
    .\publish.ps1
    .\publish.ps1 -FrameworkDependent
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [switch]$FrameworkDependent
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$output = Join-Path $root 'artifacts\TapoViewer'
$decoderOutput = Join-Path $output 'decoder'

$common = @(
    '-c', $Configuration
    '-r', 'win-x64'
    '--nologo'
    '-p:PublishSingleFile=false'
    # No trimming: WPF, XAML type resolution, and the libVLC interop layer all rely on
    # reflection that a trimmer cannot see, and a trimmed build fails at runtime rather
    # than at build time.
    '-p:PublishTrimmed=false'
)

if ($FrameworkDependent) {
    $common += '--self-contained', 'false'
    Write-Host 'Mode: framework-dependent (requires .NET 8 Desktop Runtime)' -ForegroundColor Yellow
}
else {
    $common += '--self-contained', 'true'
    Write-Host 'Mode: self-contained (no .NET installation required)' -ForegroundColor Cyan
}

if (Test-Path $output) {
    Write-Host "Cleaning $output"
    Remove-Item $output -Recurse -Force
}

Write-Host ''
Write-Host '[1/2] Publishing decoder (sandboxed, low integrity at runtime)...' -ForegroundColor Cyan
& dotnet publish (Join-Path $root 'src\TapoViewer.Decoder\TapoViewer.Decoder.csproj') `
    @common -o $decoderOutput
if ($LASTEXITCODE -ne 0) { throw "Decoder publish failed with exit code $LASTEXITCODE." }

Write-Host ''
Write-Host '[2/2] Publishing UI...' -ForegroundColor Cyan
& dotnet publish (Join-Path $root 'src\TapoViewer.App\TapoViewer.App.csproj') `
    @common -o $output
if ($LASTEXITCODE -ne 0) { throw "UI publish failed with exit code $LASTEXITCODE." }

# The libVLC package ships every Windows architecture as plain content, so -r win-x64 does not
# filter it: win-arm64 gets published too, for an architecture this build cannot run on. Dropping
# it roughly halves the decoder payload.
$libvlcRoot = Join-Path $decoderOutput 'libvlc'
if (Test-Path $libvlcRoot) {
    Get-ChildItem $libvlcRoot -Directory | Where-Object { $_.Name -ne 'win-x64' } | ForEach-Object {
        $freed = [math]::Round(((Get-ChildItem $_.FullName -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)
        Remove-Item $_.FullName -Recurse -Force
        Write-Host "Pruned libvlc\$($_.Name) (freed $freed MB)"
    }
}

# Publishing the UI drops an orphaned decoder apphost (no managed assembly beside it) into the
# output root, because the build-order ProjectReference still contributes it. DecoderLocator
# ignores incomplete deployments, but removing it avoids anyone double-clicking a stub that
# cannot run.
$orphan = Join-Path $output 'TapoViewer.Decoder.exe'
if ((Test-Path $orphan) -and -not (Test-Path (Join-Path $output 'TapoViewer.Decoder.dll'))) {
    Remove-Item $orphan -Force
    Write-Host 'Removed orphaned decoder apphost from the output root.'
}

$appExe = Join-Path $output 'TapoViewer.App.exe'
$decoderExe = Join-Path $decoderOutput 'TapoViewer.Decoder.exe'
$decoderDll = Join-Path $decoderOutput 'TapoViewer.Decoder.dll'

foreach ($required in @($appExe, $decoderExe, $decoderDll)) {
    if (-not (Test-Path $required)) { throw "Expected output missing: $required" }
}

$sizeMb = [math]::Round(((Get-ChildItem $output -Recurse -File | Measure-Object Length -Sum).Sum / 1MB), 1)

Write-Host ''
Write-Host 'Publish complete.' -ForegroundColor Green
Write-Host "  Folder    : $output"
Write-Host "  Run       : $appExe"
Write-Host "  Total size: $sizeMb MB"
Write-Host ''
Write-Host 'Copy the whole TapoViewer folder to move it. TapoViewer.App.exe needs decoder\ beside it.'
