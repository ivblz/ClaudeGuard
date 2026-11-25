#Requires -Version 5.1
param(
    [Parameter(Mandatory)][string]$Archive
)
$ErrorActionPreference = 'Stop'
$zip = Get-Item -LiteralPath $Archive
$expected = ((Get-Content -LiteralPath ($zip.FullName + '.sha256') -Raw) -split '\s+')[0]
if ((Get-FileHash -LiteralPath $zip.FullName).Hash -ne $expected) {
    throw 'Release ZIP checksum mismatch.'
}
$framework = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeGuard-compiler-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $scratch
$exe = Join-Path $scratch ($zip.BaseName + '.exe')
try {
    & $compiler /nologo /optimize+ /platform:x64 /target:winexe "/out:$exe" "/resource:$($zip.FullName),payload.zip" `
        /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll `
        /reference:System.Windows.Forms.dll (Join-Path $PSScriptRoot 'Installer.cs')
    if ($LASTEXITCODE) { throw 'Could not compile the Windows installer.' }
    $test = Start-Process -FilePath $exe -ArgumentList '--smoke-test' -Wait -PassThru -WindowStyle Hidden
    if ($test.ExitCode) { throw "Installer smoke test exited with code $($test.ExitCode)." }
    $name = [IO.Path]::GetFileName($exe)
    $digest = (Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant()
    $destination = Join-Path $zip.DirectoryName $name
    Move-Item -LiteralPath $exe -Destination $destination -Force
    "$digest  $name" | Set-Content -LiteralPath ($destination + '.sha256') -Encoding Ascii
    Write-Output "Built $destination"
} finally {
    if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
    [IO.Directory]::Delete($scratch)
}
