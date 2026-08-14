$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:VCPKG_INSTALLED) { throw "VCPKG_INSTALLED is required" }
if (-not $env:VCPKG_DEFAULT_TRIPLET) { throw "VCPKG_DEFAULT_TRIPLET is required" }

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { Join-Path $RootDir ".portable-work" }
$WorkDir = Join-Path $WorkRoot "windows-$($env:PORTABLE_ARCH)"
$StageDir = Join-Path $WorkDir "stage"
$OutputDir = Join-Path $RootDir "dist"
$ArchiveName = "opensc-portable-windows-$($env:PORTABLE_ARCH).zip"

switch ($env:PORTABLE_ARCH.ToLowerInvariant()) {
    "x86" { $ExpectedMachine = '14C machine \(x86\)' }
    "x64" { $ExpectedMachine = '8664 machine \(x64\)' }
    "arm64" { $ExpectedMachine = 'AA64 machine \(ARM64\)' }
    default { throw "unsupported PORTABLE_ARCH: $($env:PORTABLE_ARCH)" }
}

Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path (Join-Path $StageDir "bin"), (Join-Path $StageDir "lib"), $OutputDir | Out-Null

Push-Location $RootDir
try {
    nmake /nologo /f Makefile.mak all
    if ($LASTEXITCODE -ne 0) { throw "OpenSC build failed" }
}
finally {
    Pop-Location
}

$Tool = Join-Path $StageDir "bin/pkcs11-tool.exe"
$OpenSCLibrary = Join-Path $StageDir "bin/opensc.dll"
$Spy = Join-Path $StageDir "lib/pkcs11-spy.dll"
Copy-Item (Join-Path $RootDir "src/tools/pkcs11-tool.exe") $Tool
Copy-Item (Join-Path $RootDir "src/libopensc/opensc.dll") $OpenSCLibrary
Copy-Item (Join-Path $RootDir "src/pkcs11/pkcs11-spy.dll") $Spy
Copy-Item (Join-Path $RootDir "packaging/portable/README.txt") (Join-Path $StageDir "README.txt")
Copy-Item (Join-Path $RootDir "COPYING") (Join-Path $StageDir "LICENSE-OpenSC.txt")
$OpenSSLCopyright = Join-Path $env:VCPKG_INSTALLED "$($env:VCPKG_DEFAULT_TRIPLET)/share/openssl/copyright"
Copy-Item $OpenSSLCopyright (Join-Path $StageDir "LICENSE-OpenSSL.txt")

foreach ($Binary in $Tool, $OpenSCLibrary, $Spy) {
    if (-not (& dumpbin /headers $Binary | Select-String -Pattern $ExpectedMachine)) {
        throw "$Binary does not have the expected $($env:PORTABLE_ARCH) machine type"
    }
    $Unexpected = & dumpbin /dependents $Binary |
        Select-String -Pattern 'libcrypto|libssl|vcruntime|msvcp|ucrtbased' -CaseSensitive:$false
    if ($Unexpected) {
        $Unexpected | Write-Error
        throw "$Binary has an unexpected runtime dependency"
    }
}

$ArchivePath = Join-Path $OutputDir $ArchiveName
Remove-Item $ArchivePath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
certutil -hashfile $ArchivePath SHA256
if ($LASTEXITCODE -ne 0) { throw "cannot calculate package SHA-256" }
