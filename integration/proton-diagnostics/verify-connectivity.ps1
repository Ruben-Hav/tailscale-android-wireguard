param(
  [string]$ControllerUri = 'http://127.0.0.1:39089',
  [string]$OutputDirectory = (Join-Path $PSScriptRoot '../../.proton-build/connectivity'),
  [string[]]$ServerNames = @('NL#799', 'NL#895', 'NL#227'),
  [ValidateRange(1, 20)]
  [int]$RecoveryCycles = 4
)
$ErrorActionPreference = 'Stop'
function Send([string]$Path, $Body = @{}) {
  Invoke-RestMethod ($ControllerUri + $Path) -Method Post -ContentType application/json -Body ($Body | ConvertTo-Json -Compress) -TimeoutSec 90
}
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
$original = Send '/state'
if (-not $original.protonLoggedIn -or -not $original.identityUnchanged) { throw 'Saved sessions unavailable' }
$servers = (Send '/servers').servers
$tls = @(); $recovery = @(); $selected = @()
try {
  foreach ($name in $ServerNames) {
    $server = $servers | Where-Object name -eq $name | Select-Object -First 1
    if (-not $server) { throw "Comparison server unavailable: $name" }
    $selected += $server
    foreach ($accelerator in @($true, $false)) {
      Send '/accelerator' @{ enabled = $accelerator } | Out-Null
      $connected = Send '/connect' @{ serverID = $server.id }
      foreach ($hostName in @('1.1.1.1', 'example.com', 'www.cloudflare.com', '1.1.1.1')) {
        $result = Send '/url' @{ host = $hostName; freshTls = $true }
        $tls += @{ server = $name; accelerator = $accelerator; connectMs = $connected.connectMs; result = $result }
      }
      Send '/disconnect' | Out-Null
    }
  }
  Send '/accelerator' @{ enabled = $original.accelerator } | Out-Null
  for ($cycle = 1; $cycle -le $RecoveryCycles; $cycle++) {
    Send '/connect' @{ serverID = $selected[-1].id } | Out-Null
    if ($cycle -eq 1) {
      $details = Send '/detail'
      $details | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputDirectory 'ipv6-detail.json')
      $direct = @($details.detail | Where-Object tls)
      if (@($direct | Where-Object { $_.response -notmatch '^HTTP/1\.[01] 200' -or $_.handshakeMs -ge 2000 }).Count -or @($direct | Where-Object { $_.address -match ':' }).Count -lt 2) {
        throw 'Per-address IPv4/IPv6 TLS verification failed; inspect ipv6-detail.json'
      }
    }
    foreach ($phase in @('on', 'off')) {
      if ($phase -eq 'off') { Send '/disconnect' | Out-Null }
      foreach ($hostName in @('example.com', 'www.cloudflare.com', '1.1.1.1')) {
        $result = Send '/url' @{ host = $hostName }
        $recovery += @{ cycle = $cycle; phase = $phase; result = $result }
      }
    }
  }
} finally {
  $tls | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'tls.json')
  $recovery | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutputDirectory 'recovery.json')
  Send '/disconnect' | Out-Null
  Send '/accelerator' @{ enabled = $original.accelerator } | Out-Null
  $final = Send '/state'
  $final | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputDirectory 'sessions.json')
  if (-not $final.protonLoggedIn -or -not $final.identityUnchanged -or $final.nodeFingerprint -ne $original.nodeFingerprint) { throw 'Saved session or node changed' }
}
$bad = @($tls + $recovery | Where-Object { $_.result.status -ne 200 -or $_.result.ms -ge 2000 })
if ($bad.Count) { throw "$($bad.Count) HTTP/TLS requests failed or took >=2 seconds; inspect artifacts" }
"PASS: $($tls.Count) immediate TLS and $($recovery.Count) transition requests; saved sessions preserved"
