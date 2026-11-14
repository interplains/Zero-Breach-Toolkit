# Scan Windows programs with Microsoft Defender, with today's definitions, without removing anything.
#
#   pwsh tools/defender_scan.ps1 out/zero-breach-toolkit-windows-x64.exe [more files...]
#
# Exits 1 when Defender flags a file (or a file has vanished, which is what a quarantine looks like), so a
# false positive is found before people download the program. When Defender is not available on the machine
# it says so and exits 0: a missing scanner is reported, never mistaken for a clean result.
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files)

$mp = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
if (-not (Test-Path $mp)) {
    Write-Output "::warning::Microsoft Defender is not available on this machine; the scan did not run"
    exit 0
}
& $mp -SignatureUpdate | Out-Host
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($status) {
    Write-Output ("Defender definitions {0} ({1})" -f $status.AntivirusSignatureVersion, $status.AntivirusSignatureLastUpdated)
}
$flagged = $false
foreach ($f in $Files) {
    if (-not (Test-Path $f)) {
        Write-Output "::error::$f is missing - it may have been quarantined"
        $flagged = $true
        continue
    }
    $full = (Resolve-Path $f).Path
    & $mp -Scan -ScanType 3 -File $full -DisableRemediation | Out-Host
    $code = $LASTEXITCODE
    if ($code -eq 2) {
        Write-Output "::error::Microsoft Defender flags $f"
        $flagged = $true
    } elseif ($code -ne 0) {
        Write-Output "::warning::Defender could not finish scanning $f (exit $code); not a clean result"
    } else {
        Write-Output "Defender: no threat found in $f"
    }
}
if ($flagged) { exit 1 }
exit 0
