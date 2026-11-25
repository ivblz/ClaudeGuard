#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$NoLaunch,
    [switch]$EnableStartup,
    [switch]$ShowErrors,
    [string]$InstallingSid
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
if ($InstallingSid -and $InstallingSid -ne $sid) {
    throw 'Install ClaudeGuard from the administrator account that will use it.'
}
if (!([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-InstallingSid', $sid)
    foreach ($option in 'Uninstall', 'NoLaunch', 'EnableStartup', 'ShowErrors') {
        if ($PSBoundParameters[$option]) { $arguments += "-$option" }
    }
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $process = Start-Process $powershell -ArgumentList $arguments -Verb RunAs -Wait -PassThru
    exit $process.ExitCode
}
$programs = [Environment]::GetFolderPath('ProgramFiles')
$folderName = "ClaudeGuard-$sid"
$installDir = Join-Path $programs $folderName
$legacyDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\ClaudeGuard'
$legacyApp = Join-Path $legacyDir 'ClaudeGuard.exe'
$appPath = Join-Path $installDir 'ClaudeGuard.exe'
$marker = '.claudeguard-installed'
$installKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard'
$shell = New-Object -ComObject WScript.Shell
$shortcuts = @('Programs', 'DesktopDirectory') | ForEach-Object {
    Join-Path ([Environment]::GetFolderPath($_)) 'ClaudeGuard.lnk'
}

function Assert-ApplicationStopped {
    if (Get-Process -Name ClaudeGuard -ErrorAction SilentlyContinue |
        Where-Object { $_.MainModule.FileVersionInfo.FileDescription -ne 'ClaudeGuard Installer' }) {
        throw 'Quit ClaudeGuard from the notification area and run setup again.'
    }
}

function Assert-PlainDirectory {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Expected a regular folder at $Path."
    }
}

function Assert-Installation {
    Assert-PlainDirectory $installDir
    if (!(Test-Path -LiteralPath (Join-Path $installDir $marker) -PathType Leaf)) {
        throw "Setup does not own the folder at $installDir."
    }
}

function Assert-PlainContents {
    param([string]$Path)
    if (Get-ChildItem -LiteralPath $Path -Force -Recurse -Attributes ReparsePoint | Select-Object -First 1) {
        throw "The folder at $Path contains a junction or symbolic link."
    }
}

function Assert-ProgramFolder {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    $programRoot = (Resolve-Path -LiteralPath $programs).ProviderPath
    if (!$item.PSIsContainer -or $item.Parent.FullName -ne $programRoot -or
        $item.Name -notmatch ("^" + [regex]::Escape($folderName) + '(?:\.(?:new|old)-[0-9a-f]{32})?$')) {
        throw "Unexpected application folder $Path."
    }
    Assert-PlainDirectory $Path
    Assert-PlainContents $Path
}

function Remove-ProgramFolder {
    param([string]$Path)
    Assert-ProgramFolder $Path
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Test-OurShortcut {
    param([string]$Path)
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    return $shell.CreateShortcut($Path).TargetPath -in @($appPath, $legacyApp)
}

function Invoke-ApplicationMaintenance {
    param([string]$Argument)
    $process = Start-Process -FilePath $appPath -WorkingDirectory $installDir -ArgumentList $Argument `
        -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "ClaudeGuard $Argument exited with code $($process.ExitCode)."
    }
}

function Install-ClaudeGuard {
    $sourceApp = Join-Path $PSScriptRoot 'ClaudeGuard.exe'
    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($sourceApp)
    if ($version.FileDescription -ne 'ClaudeGuard') {
        throw 'Extract the entire ClaudeGuard ZIP before running Install.cmd.'
    }
    $payload = @('_internal', 'licenses', 'ClaudeGuard.exe', 'sing-box.exe', 'libcronet.dll',
        'LICENSE', 'NOTICE', 'README.md', 'Setup.ps1', 'Uninstall.cmd')
    foreach ($name in $payload) {
        $item = Get-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Unexpected link in the package at $($item.FullName)."
        }
        if ($item.PSIsContainer) {
            Assert-PlainContents $item.FullName
        }
    }

    $null = New-Item -ItemType Directory -Path $programs -Force
    Assert-PlainDirectory $programs
    $upgrade = Test-Path -LiteralPath $installDir
    if ($upgrade) {
        Assert-Installation
        Assert-ProgramFolder $installDir
    }
    foreach ($shortcut in $shortcuts) {
        if ((Test-Path -LiteralPath $shortcut) -and !(Test-OurShortcut $shortcut)) {
            throw "A different shortcut already exists at $shortcut."
        }
    }

    $id = [guid]::NewGuid().ToString('N')
    $stage = Join-Path $programs "$folderName.new-$id"
    $backup = Join-Path $programs "$folderName.old-$id"
    $null = New-Item -ItemType Directory -Path $stage
    try {
        foreach ($name in $payload) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $stage -Recurse
        }
        $null = New-Item -ItemType File -Path (Join-Path $stage $marker)
        $test = Start-Process -FilePath (Join-Path $stage 'ClaudeGuard.exe') -WorkingDirectory $stage `
            -ArgumentList '--smoke-test' -WindowStyle Hidden -Wait -PassThru
        if ($test.ExitCode -ne 0) {
            throw "ClaudeGuard could not start from the staged files (exit code $($test.ExitCode))."
        }
        Assert-ApplicationStopped
        if ($upgrade) {
            Assert-ProgramFolder $installDir
            [IO.Directory]::Move($installDir, $backup)
        }
        try {
            Assert-ProgramFolder $stage
            [IO.Directory]::Move($stage, $installDir)
        } catch {
            if ($upgrade) {
                Assert-ProgramFolder $backup
                [IO.Directory]::Move($backup, $installDir)
            }
            throw
        }
    } finally {
        if (Test-Path -LiteralPath $stage) {
            Remove-ProgramFolder $stage
        }
    }
    if ($upgrade) {
        Remove-ProgramFolder $backup
    }

    foreach ($shortcut in $shortcuts) {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $shortcut) -Force
        $link = $shell.CreateShortcut($shortcut)
        $link.TargetPath = $appPath
        $link.WorkingDirectory = $installDir
        $link.Description = 'ClaudeGuard'
        $link.Save()
    }

    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $setup = Join-Path $installDir 'Setup.ps1'
    $uninstallCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}" -Uninstall -ShowErrors' -f $powershell, $setup
    $null = New-Item -Path $installKey -Force
    $properties = @{
        DisplayName = 'ClaudeGuard'
        DisplayIcon = '"{0}",0' -f $appPath
        InstallLocation = $installDir
        UninstallString = $uninstallCommand
        NoModify = 1
        NoRepair = 1
    }
    if ((Get-Item -LiteralPath $installKey).GetValueNames() -contains 'DisplayVersion') {
        Remove-ItemProperty -LiteralPath $installKey -Name DisplayVersion
    }
    foreach ($property in $properties.GetEnumerator()) {
        $propertyType = if ($property.Value -is [int]) { 'DWord' } else { 'String' }
        $null = New-ItemProperty -LiteralPath $installKey -Name $property.Key -Value $property.Value `
            -PropertyType $propertyType -Force
    }

    $task = Get-ScheduledTask -TaskName "ClaudeGuard-$sid" -ErrorAction SilentlyContinue
    $legacyInstalled = (Test-Path -LiteralPath (Join-Path $legacyDir $marker) -PathType Leaf)
    if ((!$upgrade -and !$legacyInstalled) -or $EnableStartup -or ($task -and $task.State -ne 'Disabled')) {
        try {
            Invoke-ApplicationMaintenance '--enable-startup'
        } catch {
            throw "ClaudeGuard is installed. To enable sign-in startup, reopen ClaudeGuard and use its tray menu. $($_.Exception.Message)"
        }
    }
    if (!$NoLaunch) {
        Start-Process -FilePath $appPath -WorkingDirectory $installDir -WindowStyle Hidden
    }
    Write-Output "ClaudeGuard is installed in $installDir."
}

function Remove-ClaudeGuardData {
    $roaming = (Resolve-Path -LiteralPath ([Environment]::GetFolderPath('ApplicationData'))).ProviderPath
    $target = Join-Path $roaming 'ClaudeGuard'
    if (!(Test-Path -LiteralPath $target)) { return }
    Assert-PlainDirectory $target
    $resolved = (Resolve-Path -LiteralPath $target).ProviderPath
    if ([IO.Path]::GetDirectoryName($resolved) -ne $roaming -or
        [IO.Path]::GetFileName($resolved) -ne 'ClaudeGuard') {
        throw 'Unexpected ClaudeGuard settings directory.'
    }
    Assert-PlainContents $resolved
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Uninstall-ClaudeGuard {
    Assert-Installation
    Assert-ProgramFolder $installDir
    Assert-ApplicationStopped
    Set-Location -LiteralPath $programs
    [Environment]::CurrentDirectory = $programs
    Invoke-ApplicationMaintenance '--disable-protection'
    Remove-ClaudeGuardData
    foreach ($shortcut in $shortcuts) {
        if (Test-OurShortcut $shortcut) {
            Remove-Item -LiteralPath $shortcut -Force
        }
    }
    Remove-ProgramFolder $installDir
    if (Test-Path -LiteralPath $installKey) {
        Remove-Item -LiteralPath $installKey -Force
    }
    Write-Output 'ClaudeGuard was uninstalled. Saved IPs, proxy credentials, and runtime data were removed.'
}

$mutex = [Threading.Mutex]::new($false, "Global\ClaudeGuard-Setup-$sid")
$ownsMutex = $false
try {
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (!$ownsMutex) {
        throw 'ClaudeGuard setup is already running.'
    }
    if ($Uninstall) {
        Uninstall-ClaudeGuard
    } else {
        Install-ClaudeGuard
    }
} catch {
    if ($ShowErrors) {
        $null = $shell.Popup($_.Exception.Message, 0, 'ClaudeGuard Setup', 16)
    }
    throw
} finally {
    if ($ownsMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
