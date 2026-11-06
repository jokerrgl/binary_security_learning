# find_oep.ps1 — 用行为判定真实入口点: 逐个候选 OEP 打补丁并试跑
#   正确入口: 进程能正常走到 main(未提权 -> 打印提示后返回退出码 1)
#   错误入口: 立即访问违例 0xC0000005 / 其他异常码
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [int]$MaxCandidates = 400,
  [int]$WaitMs = 1500
)
$ErrorActionPreference = 'Stop'
$bytes = [System.IO.File]::ReadAllBytes($Exe)
$lf = [BitConverter]::ToInt32($bytes, 0x3C)
$opt = $lf + 24
$entryOff = $opt + 16
$table = @{}
$pdataRva = [BitConverter]::ToUInt32($bytes, $opt + 112 + 8*3)   # Exception directory
$pdataSize = [BitConverter]::ToUInt32($bytes, $opt + 112 + 8*3 + 4)
$secTab = $opt + [BitConverter]::ToUInt16($bytes, $lf + 20)
$nsec = [BitConverter]::ToUInt16($bytes, $lf + 6)
function R2O([uint32]$rva) {
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secTab + $i*40
    $va = [BitConverter]::ToUInt32($bytes, $o+12); $vs = [BitConverter]::ToUInt32($bytes, $o+8); $rp = [BitConverter]::ToUInt32($bytes, $o+20)
    if ($rva -ge $va -and $rva -lt ($va + [Math]::Max($vs,1))) { return $rp + ($rva - $va) }
  }
  return -1
}
$pdataOff = R2O $pdataRva
$starts = @()
for ($i = 0; $i -lt [int]($pdataSize / 12); $i++) {
  $b = [BitConverter]::ToUInt32($bytes, $pdataOff + $i*12)
  if ($b -ge 0x1000 -and $b -lt 0x39000) { $starts += $b }
}
$starts = $starts | Sort-Object -Unique
"候选函数总数(.pdata): {0}" -f $starts.Count | Write-Host

# 找出以 sub rsp,0x28 (48 83 EC 28) 开头的函数
$preferred = @()
foreach ($s in $starts) {
  $o = 0x400 + ($s - 0x1000)
  if ($o + 4 -le $bytes.Length -and $bytes[$o] -eq 0x48 -and $bytes[$o+1] -eq 0x83 -and $bytes[$o+2] -eq 0xEC -and $bytes[$o+3] -eq 0x28) { $preferred += $s }
}
"其中 sub rsp,0x28 开头: {0}" -f $preferred.Count | Write-Host
$cands = $preferred + ($starts | Where-Object { $preferred -notcontains $_ })
if ($cands.Count -gt $MaxCandidates) { $cands = $cands[0..($MaxCandidates-1)] }

$dir = Join-Path $env:TEMP ("oep_probe_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$origEntry = [BitConverter]::GetBytes([uint32]0)
[Array]::Copy($bytes, $entryOff, $origEntry, 0, 4)

$found = $null
$results = @()
$idx = 0
foreach ($c in $cands) {
  [Array]::Copy([BitConverter]::GetBytes([uint32]$c), 0, $bytes, $entryOff, 4)
  $tmp = Join-Path $dir ("p{0}.exe" -f $idx); $idx++
  [System.IO.File]::WriteAllBytes($tmp, $bytes)
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $tmp
  $psi.WorkingDirectory = Split-Path -Parent $Exe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $p = [Diagnostics.Process]::Start($psi)
  try { $p.StandardInput.Close() } catch { }
  $lineTask = $p.StandardOutput.ReadLineAsync()
  $got = $false
  try { $got = $lineTask.Wait($WaitMs) } catch { $got = $false }
  $line = if ($got) { $lineTask.Result } else { $null }
  if (-not $p.WaitForExit(200)) { $p.Kill(); [void]$p.WaitForExit(1500) }
  $code = if ($p.HasExited) { $p.ExitCode } else { 'RUNNING' }
  $p.Dispose()
  Start-Sleep -Milliseconds 30
  Remove-Item $tmp -Force -ErrorAction SilentlyContinue
  $results += [pscustomobject]@{ EP = ('0x{0:X}' -f $c); Exit = $code; Out = $(if ($line) { $line.Substring(0, [Math]::Min(20, $line.Length)) } else { '' }) }
  if ($line -and $line.Length -gt 0) {
    $found = $c
    "命中候选 OEP = 0x{0:X} (输出: {1}, 退出码 {2})" -f $c, $line, $code | Write-Host
    break
  }
}
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
$results | ConvertTo-Json -Depth 2 | Set-Content (Join-Path $env:TEMP 'oep_probe_results.json') -Encoding UTF8
[Array]::Copy($origEntry, 0, $bytes, $entryOff, 4)
if (-not $found) {
  "未命中; 前 40 个候选的退出码:"
  $results | Select-Object -First 40 | Format-Table -AutoSize | Out-String -Width 120 | Write-Host
} else {
  "建议 OEP: 0x{0:X}" -f $found | Write-Host
}
