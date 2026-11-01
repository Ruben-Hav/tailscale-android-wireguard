param(
    [ValidateSet('cpu','allocs','block','mutex')][string]$Kind = 'cpu',
    [ValidateSet('upload','download')][string]$Direction = 'upload',
    [int]$Bytes = 16777216,
    [int]$Rate = 2097152,
    [string]$Serial = 'emulator-5554',
    [string]$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe",
    [string]$Controller = 'http://127.0.0.1:39089',
    [string]$OutputDirectory
)
# Requires PowerShell 7. Binary profiles are copied through raw .NET streams.
$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot "../../.proton-build/network/profiles/$Kind-$Direction-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff'))"
}
if ((Test-Path -LiteralPath $OutputDirectory) -and (Get-ChildItem -LiteralPath $OutputDirectory)) {
    throw 'Choose an empty profile output directory.'
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
function Command([string]$Path, $Data = @{}) {
    Invoke-RestMethod -Uri ($Controller + $Path) -Method Post -ContentType 'application/json' -Body ($Data | ConvertTo-Json -Compress) -TimeoutSec 90
}
$state = Command '/state'
if ($state.state -ne 'Connected' -or -not $state.protonLoggedIn -or -not $state.identityUnchanged) {
    throw 'The saved-session controller must have a healthy connected VPN first.'
}
$warmup = & $Adb -s $Serial shell am instrument -w -r -e direction $Direction -e bytes 1048576 -e rate 0 com.tailscale.ipn.loadtest/.Load
if ($LASTEXITCODE -ne 0 -or $warmup -notcontains 'INSTRUMENTATION_CODE: 0') { throw 'Load warmup failed.' }
$before = Command '/profile/start' @{kind=$Kind}
try {
    if ($Kind -ne 'cpu') {
        # Cumulative contention profiles must first see the steady workload.
        $samplingWarmup = & $Adb -s $Serial shell am instrument -w -r -e direction $Direction -e bytes 1048576 -e rate 0 com.tailscale.ipn.loadtest/.Load
        if ($LASTEXITCODE -ne 0 -or $samplingWarmup -notcontains 'INSTRUMENTATION_CODE: 0') { throw 'Sampling warmup failed.' }
        $before = Command '/profile/baseline'
    }
    $output = & $Adb -s $Serial shell am instrument -w -r -e direction $Direction -e bytes $Bytes -e rate $Rate com.tailscale.ipn.loadtest/.Load
    $loadExitCode = $LASTEXITCODE
    $after = Command '/state'
} finally {
    $profile = Command '/profile/stop'
}
$output | Set-Content -LiteralPath (Join-Path $OutputDirectory 'load.log')
$valid = $loadExitCode -eq 0 -and $output -contains 'INSTRUMENTATION_CODE: 0'
$line = $output | Where-Object { $_.StartsWith('INSTRUMENTATION_RESULT: stream={') } | Select-Object -First 1
$client = if ($line) { $line.Substring($line.IndexOf('{')) | ConvertFrom-Json } else { $null }
$valid = $valid -and $client -and $client.uid -ne $before.uid -and $client.pid -ne $before.pid -and $before.pid -eq $after.pid -and $client.bytes -eq $Bytes
foreach ($remote in $profile.paths) {
    if (-not $remote.Contains('/proton-profiles/') -or -not $remote.EndsWith('.pprof')) { throw 'Unexpected profile path.' }
    $local = Join-Path $OutputDirectory ([System.IO.Path]::GetFileName($remote))
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Adb; $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    foreach ($argument in @('-s',$Serial,'exec-out','run-as','com.tailscale.ipn.debug','cat',$remote)) { $psi.ArgumentList.Add($argument) }
    $process = [System.Diagnostics.Process]::Start($psi)
    $file = [System.IO.File]::Create($local)
    try { $process.StandardOutput.BaseStream.CopyTo($file) } finally { $file.Dispose() }
    $errorText = $process.StandardError.ReadToEnd(); $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "Profile copy failed: $errorText" }
    $process.Dispose()
}
$result = [pscustomobject]@{
    valid=[bool]$valid; kind=$Kind; direction=$Direction; bytes=$client.bytes
    vpnPid=$before.pid; vpnUid=$before.uid; clientPid=$client.pid; clientUid=$client.uid
    vpnCpuMs=$after.cpuMs-$before.cpuMs; clientCpuMs=$client.clientCpuMs
    vpnCpuMsPerMiB=$(if ($client.bytes -gt 0) { ($after.cpuMs-$before.cpuMs)/($client.bytes/1048576.0) } else { $null })
    profile=$profile; before=$before; after=$after
}
$result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json')
$result | Select-Object kind,direction,bytes,vpnCpuMs,clientCpuMs,vpnCpuMsPerMiB,vpnUid,clientUid
if (-not $valid) { throw 'Invalid workload or process separation; saved profiles must be excluded from comparisons.' }
