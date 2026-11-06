# final_dump.ps1 — 最后一次抓取: 主模块内存镜像 + 已加载模块列表(名字/基址/大小)
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [int]$WaitMs = 1200
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
[StructLayout(LayoutKind.Sequential)] public struct MBIF { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public ushort PartitionId; public ulong RegionSize; public uint State; public uint Protect; public uint Type; }
public static class F {
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool VirtualProtectEx(IntPtr h, IntPtr addr, IntPtr size, uint np, out uint op);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern ulong VirtualQueryEx(IntPtr h, IntPtr addr, out MBIF mbi, IntPtr len);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
  [DllImport("psapi.dll", SetLastError=true)] public static extern bool EnumProcessModulesEx(IntPtr h, IntPtr[] mods, int cb, out int needed, uint filter);
  [DllImport("psapi.dll", CharSet=CharSet.Unicode)] public static extern uint GetModuleBaseName(IntPtr h, IntPtr mod, StringBuilder name, int size);
  [DllImport("psapi.dll", CharSet=CharSet.Unicode)] public static extern uint GetModuleFileNameEx(IntPtr h, IntPtr mod, StringBuilder name, int size);
  [DllImport("psapi.dll")] public static extern bool GetModuleInformation(IntPtr h, IntPtr mod, out MODINFO mi, int cb);
}
[StructLayout(LayoutKind.Sequential)] public struct MODINFO { public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }
"@

$p = Start-Process -FilePath $Exe -WorkingDirectory (Split-Path -Parent $Exe) -PassThru
"启动 PID={0}" -f $p.Id | Write-Host
Start-Sleep -Milliseconds $WaitMs
$p.Refresh()
if ($p.HasExited) { throw "进程已退出" }

$h = [F]::OpenProcess(0x418, $false, $p.Id)
if ($h -eq [IntPtr]::Zero) { throw "OpenProcess 失败" }
[void][F]::NtSuspendProcess($h)
Start-Sleep -Milliseconds 250

$base = $p.MainModule.BaseAddress.ToInt64()
$imgSize = $p.MainModule.ModuleMemorySize
$img = New-Object byte[] $imgSize
$bad = @()
for ($off = 0; $off -lt $imgSize; $off += 0x1000) {
  $va = $base + $off
  $m = New-Object MBIF
  $q = [F]::VirtualQueryEx($h, [IntPtr][long]$va, [ref]$m, [IntPtr]48)
  $len = [Math]::Min(0x1000, $imgSize - $off)
  $buf = New-Object byte[] $len
  $read = [IntPtr]::Zero
  $ok = $false
  if ($q -ne 0 -and $m.State -eq 0x1000) {
    $ok = [F]::ReadProcessMemory($h, [IntPtr][long]$va, $buf, [IntPtr][long]$len, [ref]$read)
    if (-not $ok) {
      $old = 0
      if ([F]::VirtualProtectEx($h, [IntPtr][long]$va, [IntPtr][long]$len, 0x04, [ref]$old)) {
        $ok = [F]::ReadProcessMemory($h, [IntPtr][long]$va, $buf, [IntPtr][long]$len, [ref]$read)
        [void][F]::VirtualProtectEx($h, [IntPtr][long]$va, [IntPtr][long]$len, $old, [ref]$old)
      }
    }
  }
  if ($ok) { [Array]::Copy($buf, 0, $img, $off, $len) } else { $bad += ('0x{0:X}' -f $off) }
}
[System.IO.File]::WriteAllBytes((Join-Path $OutDir 'main_image.bin'), $img)
"主模块镜像写入; 读不到: {0}" -f ($bad -join ',') | Write-Host

# 模块列表
$mods = New-Object IntPtr[] 1024
$needed = 0
[void][F]::EnumProcessModulesEx($h, $mods, ($mods.Length * [IntPtr]::Size), [ref]$needed, 0x03)
$cnt = [int]($needed / [IntPtr]::Size)
"模块数 = $cnt" | Write-Host
$list = @()
for ($i = 0; $i -lt $cnt; $i++) {
  $mi = New-Object MODINFO
  [void][F]::GetModuleInformation($h, $mods[$i], [ref]$mi, [System.Runtime.InteropServices.Marshal]::SizeOf([type][MODINFO]))
  $sb = New-Object System.Text.StringBuilder 260
  [void][F]::GetModuleBaseName($h, $mods[$i], $sb, 260)
  $sf = New-Object System.Text.StringBuilder 520
  [void][F]::GetModuleFileNameEx($h, $mods[$i], $sf, 520)
  $list += [pscustomobject]@{ name = $sb.ToString(); base = ('0x{0:X}' -f $mi.lpBaseOfDll.ToInt64()); size = ('0x{0:X}' -f $mi.SizeOfImage); path = $sf.ToString() }
}
$list | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutDir 'modules.json') -Encoding UTF8
$list | Format-Table -AutoSize name, base, size | Out-String -Width 200 | Write-Host

[void][F]::CloseHandle($h)
$p.Kill()
"完成" | Write-Host
