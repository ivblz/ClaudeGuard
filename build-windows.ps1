#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Python = 'python.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Executable exited with code $LASTEXITCODE."
    }
}

$checkPython = "import platform, struct, sys, tkinter; sys.exit(not (platform.machine() == 'AMD64' and struct.calcsize('P') == 8 and sys.version_info[:2] == (3, 14)))"
& $Python -c $checkPython
if ($LASTEXITCODE -ne 0) {
    throw 'Building ClaudeGuard requires x64 CPython 3.14 for Windows with Tcl/Tk and venv.'
}

$root = $PSScriptRoot
$buildRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'ClaudeGuardBuild'
$distRoot = Join-Path $root 'dist'
$null = New-Item -ItemType Directory -Force -Path $buildRoot, $distRoot
$stage = Join-Path $buildRoot ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage

$engineVersion = '1.14.4'
$engineName = "sing-box-$engineVersion-windows-amd64"
$engineDigest = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
$engineZip = Join-Path $buildRoot "$engineName.zip"
$archiveName = 'ClaudeGuard.zip'

try {
    if (!(Test-Path -LiteralPath $engineZip -PathType Leaf) -or
        (Get-FileHash -LiteralPath $engineZip -Algorithm SHA256).Hash -ne $engineDigest) {
        $download = Join-Path $stage "$engineName.zip"
        Invoke-Checked curl.exe @(
            '--fail', '--location', '--silent', '--show-error', '--proto', '=https',
            '--tlsv1.2', '--connect-timeout', '20', '--max-time', '240', '--retry', '2',
            '--output', $download,
            "https://github.com/SagerNet/sing-box/releases/download/v$engineVersion/$engineName.zip"
        )
        if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash -ne $engineDigest) {
            throw 'The downloaded sing-box archive did not match its pinned SHA-256.'
        }
        Move-Item -LiteralPath $download -Destination $engineZip -Force
    }
    Expand-Archive -LiteralPath $engineZip -DestinationPath $stage
    $engine = Join-Path $stage $engineName

    $venv = Join-Path $stage 'venv'
    Invoke-Checked $Python @('-m', 'venv', $venv)
    $buildPython = Join-Path $venv 'Scripts\python.exe'
    Invoke-Checked $buildPython @(
        '-m', 'pip', '--disable-pip-version-check', 'install', '--only-binary=:all:',
        '-r', (Join-Path $root 'requirements-windows.txt')
    )

    $iconPath = Join-Path $root 'assets\AppIcon.png'
    $builtApps = Join-Path $stage 'application'
    Invoke-Checked $buildPython @(
        '-m', 'PyInstaller', '--noconfirm', '--onedir', '--windowed', '--noupx',
        '--name', 'ClaudeGuard', '--icon', $iconPath, '--version-file', (Join-Path $root 'packaging\windows\version-info.txt'),
        '--hidden-import', 'pystray._win32', '--add-data', "$iconPath;assets",
        '--paths', $root, '--paths', (Join-Path $root 'src'),
        '--workpath', (Join-Path $stage 'pyinstaller'), '--specpath', $stage,
        '--distpath', $builtApps, (Join-Path $root 'src\windows\windows_app.py')
    )

    $app = Join-Path $builtApps 'ClaudeGuard'
    $licenses = Join-Path $app 'licenses'
    $null = New-Item -ItemType Directory -Path $licenses
    Copy-Item -LiteralPath (Join-Path $engine 'sing-box.exe'), (Join-Path $engine 'libcronet.dll') -Destination $app
    Copy-Item -LiteralPath (Join-Path $engine 'LICENSE') -Destination (Join-Path $licenses 'sing-box.txt')
    Copy-Item -LiteralPath (Join-Path $root 'LICENSE'), (Join-Path $root 'NOTICE') -Destination $app
    foreach ($file in 'README.md', 'Install.cmd', 'Setup.ps1', 'Uninstall.cmd') {
        Copy-Item -LiteralPath (Join-Path $root "packaging\windows\$file") -Destination $app
    }
    Invoke-Checked $buildPython @(
        (Join-Path $root 'packaging\windows\copy-licenses.py'), $licenses
    )

    $guardExe = Join-Path $app 'ClaudeGuard.exe'
    $check = Start-Process -FilePath $guardExe -ArgumentList '--smoke-test' -Wait -PassThru -WindowStyle Hidden
    if ($check.ExitCode) { throw "Packaged ClaudeGuard smoke test exited with code $($check.ExitCode)." }
    Invoke-Checked (Join-Path $app 'sing-box.exe') @('version')

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archivePath = Join-Path $stage $archiveName
    [IO.Compression.ZipFile]::CreateFromDirectory($app, $archivePath, [IO.Compression.CompressionLevel]::Optimal, $true)
    $digest = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = "$archivePath.sha256"
    "$digest  $archiveName" | Set-Content -LiteralPath $checksumPath -Encoding Ascii
    Move-Item -LiteralPath $archivePath -Destination $distRoot -Force
    Move-Item -LiteralPath $checksumPath -Destination $distRoot -Force
    & (Join-Path $root 'packaging\windows\build-installer.ps1') -Archive (Join-Path $distRoot $archiveName)
    Write-Output "Built $(Join-Path $distRoot $archiveName)"
} finally {
    $resolvedStage = (Resolve-Path -LiteralPath $stage).ProviderPath
    $resolvedBuildRoot = (Resolve-Path -LiteralPath $buildRoot).ProviderPath
    if ([IO.Path]::GetDirectoryName($resolvedStage) -eq $resolvedBuildRoot) {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
