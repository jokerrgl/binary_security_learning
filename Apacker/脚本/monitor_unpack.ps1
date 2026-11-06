# monitor_unpack.ps1 — 不依赖调试器：启动样本(非管理员) -> 轮询等待 .text 解密 -> NtSuspendProcess
#                    -> 读取内存镜像落盘(原始布局) -> 结束进程
# 用法: .\monitor_unpack.ps1 -Exe ...\Campus_Network_learning.exe -OutDir ...\unpack_work

param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [int]$TimeoutMs = 25000
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class U {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
}
"@

$src = [System.IO.File]::ReadAllBytes($Exe)
$srcTextOff = 0x400
$TEXT_RVA   = 0x1000

$p = Start-Process -FilePath $Exe -WorkingDirectory (Split-Path -Parent $Exe) -PassThru
"已启动 PID={0} (非管理员, 无提权)" -f $p.Id | Write-Host

$p.Refresh()
if ($p.HasExited) { throw "进程启动后立刻退出, ExitCode=$($p.ExitCode)" }
$base = $p.MainModule.BaseAddress.ToInt64()
"主模块基址 = 0x{0:X}" -f $base | Write-Host

$h = [U]::OpenProcess(0x1010, $false, $p.Id)
if ($h -eq [IntPtr]::Zero) { throw "OpenProcess 失败 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

function ReadAt([int64]$addr, [int]$n) {
  $buf = New-Object byte[] $n
  $read = [IntPtr]::Zero
  if (-not [U]::ReadProcessMemory($h, [IntPtr][long]$addr, $buf, [IntPtr][long]$n, [ref]$read)) { return $null }
  return $buf
}

# 采样点: 壳自己加的加密节 + 原 .text (VA, 文件 raw 偏移)
$probes = @(
  @{VA=0x1000;  Raw=0x400},
  @{VA=0x58000; Raw=0x52E00},
  @{VA=0x63000; Raw=0x5D600},
  @{VA=0x67000; Raw=0x60C00},
  @{VA=0x6A000; Raw=0x63800}
)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$decrypted = $false
$report = @()
while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
  if ($p.HasExited) { throw "进程在 {0}ms 后退出, 内存已丢失" -f $sw.ElapsedMilliseconds }
  $changed = 0
  $report = @()
  foreach ($pr in $probes) {
    $probe = ReadAt ($base + $pr.VA) 16
    if (-not $probe) { $report += ("VA 0x{0:X}: <读取失败>" -f $pr.VA); continue }
    $same = $true
    for ($i = 0; $i -lt 16; $i++) { if ($probe[$i] -ne $src[$pr.Raw + $i]) { $same = $false; break } }
    $hex = ($probe | ForEach-Object { $_.ToString('X2') }) -join ' '
    $report += ("VA 0x{0:X6}: {1} changed={2}" -f $pr.VA, $hex, (-not $same))
    if (-not $same) { $changed++ }
  }
  # 头部数据目录里 Import 是否被壳填上
  $hdr = ReadAt ($base + 0xF8) 0x200
  $impRva = 0
  if ($hdr) {
    $opt = 0x18
    $impRva = [BitConverter]::ToUInt32($hdr, $opt + 112 + 8)
  }
  if ($changed -ge 2 -or $impRva -ne 0) { $decrypted = $true; break }
  Start-Sleep -Milliseconds 5
}

"等待 {0} ms; 采样判定 .text 解密 = {1}" -f $sw.ElapsedMilliseconds, $decrypted | Write-Host
$report | ForEach-Object { "  $_" | Write-Host }

[void][U]::NtSuspendProcess($h)
Start-Sleep -Milliseconds 300

$imgSize = $p.MainModule.ModuleMemorySize
$img = New-Object byte[] $imgSize
$got = 0
while ($got -lt $imgSize) {
  $n = [Math]::Min(0x1000, $imgSize - $got)
  $tmp = ReadAt ($base + $got) $n
  if (-not $tmp) { throw ("读取镜像失败 @0x{0:X}" -f ($base + $got)) }
  [Array]::Copy($tmp, 0, $img, $got, $n)
  $got += $n
}
[void][U]::CloseHandle($h)

$imgPath = Join-Path $OutDir 'image.bin'
[System.IO.File]::WriteAllBytes($imgPath, $img)
"原始内存镜像: $imgPath (0x{0:X} 字节)" -f $imgSize | Write-Host
"PID={0}`nbase=0x{1:X}`nimageSize=0x{2:X}" -f $p.Id, $base, $imgSize | Set-Content (Join-Path $OutDir 'info.txt') -Encoding UTF8

$p.Kill()
Start-Sleep -Milliseconds 200
"进程已结束: HasExited={0}" -f $p.HasExited | Write-Host
