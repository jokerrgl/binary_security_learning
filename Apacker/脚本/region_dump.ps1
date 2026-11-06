# region_dump.ps1 — 启动样本(非管理员)，等壳解完，挂起后 dump 主模块镜像(含 NOACCESS 页临时改权限读取)
#                  并导出 MEM_PRIVATE 区域，最后结束进程。
# 用法: .\region_dump.ps1 -Exe ...\Campus_Network_learning.exe -OutDir ...\unpack_work -WaitMs 1200

param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [int]$WaitMs = 1200
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential)] public struct MBIR { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public ushort PartitionId; public ulong RegionSize; public uint State; public uint Protect; public uint Type; }
public static class R2 {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint newProt, out uint old);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern ulong VirtualQueryEx(IntPtr h, IntPtr addr, out MBIR mbi, IntPtr len);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
}
"@

$p = Start-Process -FilePath $Exe -WorkingDirectory (Split-Path -Parent $Exe) -PassThru
"启动 PID={0} (非管理员)" -f $p.Id | Write-Host
Start-Sleep -Milliseconds $WaitMs
$p.Refresh()
if ($p.HasExited) { throw "进程已退出, 内存丢失" }

$h = [R2]::OpenProcess(0x418, $false, $p.Id)   # QUERY|VM_READ|VM_OPERATION
if ($h -eq [IntPtr]::Zero) { throw "OpenProcess 失败 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
[void][R2]::NtSuspendProcess($h)
Start-Sleep -Milliseconds 250

$base = $p.MainModule.BaseAddress.ToInt64()
$imgSize = $p.MainModule.ModuleMemorySize
"主模块 base=0x{0:X} size=0x{1:X}" -f $base, $imgSize | Write-Host

$img = New-Object byte[] $imgSize
$failedPages = @()
$pageMap = @()
for ($off = 0; $off -lt $imgSize; $off += 0x1000) {
  $va = $base + $off
  $m = New-Object MBIR
  $q = [R2]::VirtualQueryEx($h, [IntPtr][long]$va, [ref]$m, [IntPtr]48)
  $state = if ($q -ne 0) { $m.State } else { 0 }
  $prot  = if ($q -ne 0) { $m.Protect } else { 0 }
  $len = [Math]::Min(0x1000, $imgSize - $off)
  $buf = New-Object byte[] $len
  $read = [IntPtr]::Zero
  $ok = $false
  if ($state -eq 0x1000) {
    $ok = [R2]::ReadProcessMemory($h, [IntPtr][long]$va, $buf, [IntPtr][long]$len, [ref]$read)
    if (-not $ok) {
      $old = 0
      if ([R2]::VirtualProtectEx($h, [IntPtr][long]$va, [IntPtr][long]$len, 0x04, [ref]$old)) {
        $ok = [R2]::ReadProcessMemory($h, [IntPtr][long]$va, $buf, [IntPtr][long]$len, [ref]$read)
        [void][R2]::VirtualProtectEx($h, [IntPtr][long]$va, [IntPtr][long]$len, $old, [ref]$old)
      }
    }
  }
  if ($ok) { [Array]::Copy($buf, 0, $img, $off, $len) }
  else { $failedPages += ('0x{0:X}' -f $off) }
  $st = switch ([int]$state) { 0x1000 {"COMMIT"} 0x2000 {"RESERVE"} 0x10000 {"FREE"} default {"NONE"} }
  $pageMap += ('RVA 0x{0:X6} state={1,-8} prevProtect=0x{2:X} read={3}' -f $off, $st, $prot, $ok)
}
[void][R2]::CloseHandle($h)

$imgPath = Join-Path $OutDir 'main_image.bin'
[System.IO.File]::WriteAllBytes($imgPath, $img)
"主模块镜像: $imgPath" | Write-Host
"读不到的页(RVA): " + ($failedPages -join ', ') | Write-Host
$pageMap | Set-Content (Join-Path $OutDir 'main_pagemap.txt') -Encoding UTF8

# 顺便把所有 MEM_PRIVATE(0x20000) 已提交区域也存一份
$h = [R2]::OpenProcess(0x418, $false, $p.Id)
$privDir = Join-Path $OutDir 'private_regions'
New-Item -ItemType Directory -Force -Path $privDir | Out-Null
$ridx = 0; $saved = @()
$addr = [uint64]0x10000; $limit = [uint64]0x7FFFFFFEFFFF
while ($addr -lt $limit) {
  $m = New-Object MBIR
  if ([R2]::VirtualQueryEx($h, [IntPtr][long]$addr, [ref]$m, [IntPtr]48) -eq 0) { break }
  if ($m.RegionSize -eq 0) { break }
  $rBase = [uint64]$m.BaseAddress.ToInt64(); $rSize = [uint64]$m.RegionSize
  if ($m.State -eq 0x1000 -and $m.Type -eq 0x20000 -and $rSize -ge 0x1000) {
    $len = [int][Math]::Min($rSize, 0x800000)
    $buf = New-Object byte[] $len
    $read = [IntPtr]::Zero
    if ([R2]::ReadProcessMemory($h, [IntPtr][long]$rBase, $buf, [IntPtr][long]$len, [ref]$read)) {
      $fn = Join-Path $privDir ('p{0:D2}_{1:X}.bin' -f $ridx, $rBase)
      [System.IO.File]::WriteAllBytes($fn, $buf)
      $saved += ('0x{0:X} size=0x{1:X} prot=0x{2:X} -> {3}' -f $rBase, $rSize, $m.Protect, $fn)
      $ridx++
    }
  }
  $next = $rBase + $rSize; if ($next -le $addr) { $next = $addr + 0x1000 }
  $addr = $next
}
[void][R2]::CloseHandle($h)
$saved | ForEach-Object { "PRIVATE $_" | Write-Host }
$saved | Set-Content (Join-Path $OutDir 'private_regions.txt') -Encoding UTF8
$p.Kill()
"进程已结束" | Write-Host
