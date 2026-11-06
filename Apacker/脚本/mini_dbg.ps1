# mini_dbg.ps1 — 极简调试器: 只用来抓第一次异常(代码/地址/故障地址/RIP)
param([Parameter(Mandatory=$true)][string]$Exe, [int]$TimeoutMs = 15000)

Add-Type -TypeDefinition @"
using System; using System.Text; using System.Runtime.InteropServices;
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct SI { public int cb; public string r1, r2, r3; public int x1, x2, x3, x4; public short w1, w2; public short r4, r5, r6, r7; public int y1, y2, y3, y4; public IntPtr h1, h2, h3; }
[StructLayout(LayoutKind.Sequential)]
public struct PI { public IntPtr hProcess, hThread; public int pid, tid; }
public static class D {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref SI si, out PI pi);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool WaitForDebugEvent(byte[] ev, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ContinueDebugEvent(int pid, int tid, uint status);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetThreadContext(IntPtr h, IntPtr ctx);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr s, out IntPtr r);
}
"@
$si = New-Object SI
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf([type][SI])
$pi = New-Object PI
$ok = [D]::CreateProcess($Exe, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x2, [IntPtr]::Zero, (Split-Path -Parent $Exe), [ref]$si, [ref]$pi)
if (-not $ok) { throw ("CreateProcess 失败: " + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
"已启动(调试) pid={0} tid={1}" -f $pi.pid, $pi.tid | Write-Host

$ev = New-Object byte[] 256
$sw = [Diagnostics.Stopwatch]::StartNew()
$reported = $false
$DBG_CONTINUE = [Convert]::ToUInt32('00010002', 16)
$DBG_NOT_HANDLED = [Convert]::ToUInt32('80010001', 16)
$EX_BP = [Convert]::ToUInt32('80000003', 16)
$ctxPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1232)
while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
  if (-not [D]::WaitForDebugEvent($ev, 1000)) { continue }
  $code = [BitConverter]::ToInt32($ev, 0)
  $dpid = [BitConverter]::ToInt32($ev, 4)
  $dtid = [BitConverter]::ToInt32($ev, 8)
  if ($code -eq 1) {   # EXCEPTION_DEBUG_EVENT
    $exCode = [BitConverter]::ToUInt32($ev, 16)
    $exAddr = [BitConverter]::ToUInt64($ev, 32)
    $nParam = [BitConverter]::ToUInt32($ev, 40)
    $info0 = if ($nParam -ge 1) { [BitConverter]::ToUInt64($ev, 48) } else { 0 }
    $info1 = if ($nParam -ge 2) { [BitConverter]::ToUInt64($ev, 56) } else { 0 }
    if ($exCode -ne $EX_BP) {
      "异常: 代码=0x{0:X8} 指令地址=0x{1:X} 参数数={2} info0(RW)={3} 故障地址=0x{4:X}" -f $exCode, $exAddr, $nParam, $info0, $info1 | Write-Host
      for ($k = 0; $k -lt 1232; $k++) { [System.Runtime.InteropServices.Marshal]::WriteByte($ctxPtr, $k, 0) }
      [System.Runtime.InteropServices.Marshal]::WriteInt32($ctxPtr, 0x30, 0x00100001)
      if ([D]::GetThreadContext($pi.hThread, $ctxPtr)) {
        $m = [System.Runtime.InteropServices.Marshal]
        $rip = $m::ReadInt64($ctxPtr, 0xF8)
        $rsp = $m::ReadInt64($ctxPtr, 0x98)
        "  RIP=0x{0:X} RSP=0x{1:X} RCX=0x{2:X} RDX=0x{3:X}" -f $rip, $rsp, $m::ReadInt64($ctxPtr,0x80), $m::ReadInt64($ctxPtr,0x88) | Write-Host
        $stk = New-Object byte[] 64
        $rd = [IntPtr]::Zero
        if ([D]::ReadProcessMemory($pi.hProcess, [IntPtr][long]$rsp, $stk, [IntPtr][long]64, [ref]$rd)) {
          $ret = [BitConverter]::ToUInt64($stk, 0)
          "  栈顶(返回地址)=0x{0:X}  call 指令约在 0x{1:X}" -f $ret, ($ret - 5) | Write-Host
          "  栈内容: {0}" -f (($stk[0..39] | ForEach-Object { $_.ToString('X2') }) -join ' ') | Write-Host
        }
      } else { "  GetThreadContext 失败: " + [Runtime.InteropServices.Marshal]::GetLastWin32Error() | Write-Host }
      $reported = $true
    }
  } elseif ($code -eq 5) {   # EXIT_PROCESS_DEBUG_EVENT
    "进程退出: 退出码=0x{0:X}" -f ([BitConverter]::ToUInt32($ev, 16)) | Write-Host
    [void][D]::ContinueDebugEvent($dpid, $dtid, $DBG_CONTINUE)
    break
  }
  if ($reported) {
    "  (结束进程)" | Write-Host
    [void][D]::TerminateProcess($pi.hProcess, 0)
    [void][D]::ContinueDebugEvent($dpid, $dtid, $DBG_NOT_HANDLED)
    Start-Sleep -Milliseconds 200
    break
  }
  [void][D]::ContinueDebugEvent($dpid, $dtid, $DBG_CONTINUE)
}
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ctxPtr)
[void][D]::CloseHandle($pi.hThread); [void][D]::CloseHandle($pi.hProcess)

