# unpack_dump.ps1 — 从暂停/挂起的进程里 dump 已经解密的 PE 镜像，并重建为可执行文件
# 用法:
#   .\unpack_dump.ps1 -Pid 1234 -Base 0x7ff730740000 -SizeOfImage 0x6E000 -Out .\unpacked.exe [-Oep 0x1234]
# 说明: 只读 ReadProcessMemory(不注入、不改对方内存), 不需要管理员权限(同用户同架构)。

param(
  [Parameter(Mandatory=$true)][int]$ProcId,
  [Parameter(Mandatory=$true)][string]$Base,
  [Parameter(Mandatory=$true)][string]$SizeOfImage,
  [Parameter(Mandatory=$true)][string]$Out,
  [string]$Oep = "",
  [string]$Evidence = "",
  [switch]$NoRebuild
)

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Nt {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
"@

$PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
$PROCESS_VM_READ = 0x10

$base = [Convert]::ToUInt64($Base, 16)
$imgSize = [Convert]::ToUInt64($SizeOfImage, 16)
if ($imgSize -eq 0 -or $imgSize -gt 0x4000000) { throw "SizeOfImage 不合理: $SizeOfImage" }

$h = [Nt]::OpenProcess($PROCESS_QUERY_LIMITED_INFORMATION -bor $PROCESS_VM_READ, $false, $ProcId)
if ($h -eq [IntPtr]::Zero) { throw ("OpenProcess 失败, Win32Error=" + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
try {
  $img = New-Object byte[] $imgSize
  $chunk = 0x1000
  $got = 0
  while ($got -lt $imgSize) {
    $n = [Math]::Min($chunk, $imgSize - $got)
    $tmp = New-Object byte[] $n
    $read = [IntPtr]::Zero
    $ok = [Nt]::ReadProcessMemory($h, [IntPtr][long]($base + $got), $tmp, [IntPtr][long]$n, [ref]$read)
    if (-not $ok) { throw ("ReadProcessMemory 失败 @0x{0:X}, Win32Error={1}" -f ($base+$got), [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    [Array]::Copy($tmp, 0, $img, $got, $n)
    $got += $n
  }
} finally {
  [void][Nt]::CloseHandle($h)
}

"读到内存镜像: 0x{0:X} 字节 @ 0x{1:X}" -f $imgSize, $base | Write-Host

function U16([int]$o) { [BitConverter]::ToUInt16($img, $o) }
function U32([int]$o) { [BitConverter]::ToUInt32($img, $o) }
function U64([int]$o) { [BitConverter]::ToUInt64($img, $o) }
function W32([int]$o, [uint32]$v) { [Array]::Copy([BitConverter]::GetBytes($v), 0, $img, $o, 4) }
function W64([int]$o, [uint64]$v) { [Array]::Copy([BitConverter]::GetBytes($v), 0, $img, $o, 8) }

if ((U16 0) -ne 0x5A4D) { throw "内存镜像 DOS 头损坏" }
$lf = U32 0x3C
if ((U32 $lf) -ne 0x4550) { throw "内存镜像 PE 头损坏" }
$opt = $lf + 24
$magic = U16 $opt
$nsec = U16 ($lf + 6)
$secTab = $opt + (U16 ($lf + 20))
$fileAlignOff = $opt + 36
$sectAlignOff = $opt + 32
$entryOff = $opt + 16
$ddOff = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }

"PE: {0} 节, magic=0x{1:X}, 内存 EP=0x{2:X}, 内存 FileAlign=0x{3:X}, SectAlign=0x{4:X}" -f `
  $nsec, $magic, (U32 $entryOff), (U32 $fileAlignOff), (U32 $sectAlignOff) | Write-Host

$sectAlign = U32 $sectAlignOff
if ($sectAlign -eq 0) { $sectAlign = 0x1000 }

# ---- 1. 先原样保存内存镜像, 便于取证
if ($Evidence) {
  [System.IO.File]::WriteAllBytes($Evidence, $img)
  "原始内存镜像已保存: $Evidence ({0} 字节)" -f $imgSize | Write-Host
}

# ---- 2. 打印数据目录(判断 packer 有没有在内存里重建 Import 目录)
$ddNames = @("Export","Import","Resource","Exception","Certificate","Reloc","Debug","Arch","GlobalPtr","TLS","LoadConfig","BoundImport","IAT","DelayImport","CLR","Reserved")
"内存中的数据目录:" | Write-Host
for ($i = 0; $i -lt 16; $i++) {
  $rva = U32 ($ddOff + $i*8); $sz = U32 ($ddOff + $i*8 + 4)
  if ($rva -ne 0 -or $sz -ne 0) { "  {0,-12} RVA=0x{1:X8} Size=0x{2:X}" -f $ddNames[$i], $rva, $sz | Write-Host }
}

if ($NoRebuild) { return }

# ---- 3. 重排为文件布局: FileAlignment := SectionAlignment, raw 指针直接等于 VA
$pad = 0x200
$hdrEnd = $secTab + $nsec*40
$hdrEnd = [int]([Math]::Ceiling($hdrEnd / $pad) * $pad)
if ($hdrEnd -lt 0x400) { $hdrEnd = 0x400 }
$newHdr = $hdrEnd
$blobs = @()
$cur = $newHdr
for ($i = 0; $i -lt $nsec; $i++) {
  $o = $secTab + $i*40
  $vs = U32 ($o+8); $va = U32 ($o+12); $rs = U32 ($o+16); $rp = U32 ($o+20)
  $name = ([System.Text.Encoding]::ASCII.GetString($img, $o, 8)).Trim([char]0)
  $size = [int]([Math]::Ceiling([Math]::Max($vs,1) / $sectAlign) * $sectAlign)
  # 从内存镜像拷 VA 处的内容
  $src = [int]$va
  if ($src + $size -gt $imgSize) { $size = [int]$imgSize - $src }
  $blob = New-Object byte[] ([int]([Math]::Ceiling($size / $pad) * $pad))
  [Array]::Copy($img, $src, $blob, 0, $size)
  $blobs += [pscustomobject]@{Index=$i; Name=$name; VA=$va; VS=$vs; Size=$size; Blob=$blob; FileOff=$cur}
  $cur += $blob.Length
}

$outBytes = New-Object byte[] $cur
[Array]::Copy($img, 0, $outBytes, 0, $newHdr)
foreach ($b in $blobs) {
  [Array]::Copy($b.Blob, 0, $outBytes, $b.FileOff, $b.Blob.Length)
  $o = $secTab + $b.Index*40
  [Array]::Copy([BitConverter]::GetBytes([uint32]$b.FileOff), 0, $outBytes, $o+20, 4)   # PointerToRawData
  [Array]::Copy([BitConverter]::GetBytes([uint32]$b.Blob.Length), 0, $outBytes, $o+16, 4) # SizeOfRawData
  "节 {0,-10} VA=0x{1:X8} VSize=0x{2:X} -> fileOff=0x{3:X8} rawSize=0x{4:X}" -f $b.Name, $b.VA, $b.VS, $b.FileOff, $b.Blob.Length | Write-Host
}

# ---- 4. 头部字段修正
[Array]::Copy([BitConverter]::GetBytes([uint32]$sectAlign), 0, $outBytes, $fileAlignOff, 4)  # FileAlignment = 0x1000
[Array]::Copy([BitConverter]::GetBytes([uint32]$newHdr), 0, $outBytes, $opt + 60, 4)         # SizeOfHeaders
if ($Oep) {
  $oepV = [uint32]([Convert]::ToUInt64($Oep, 16) - $base)
  [Array]::Copy([BitConverter]::GetBytes($oepV), 0, $outBytes, $entryOff, 4)
  "EntryPoint := 0x{0:X} (RVA)" -f $oepV | Write-Host
}
# 关闭 ASLR(dynamic base), 让镜像落在首选基址
$dllChars = [BitConverter]::ToUInt16($outBytes, $opt + 70)
$dllChars = [uint16]($dllChars -band (-bnot 0x40))
[Array]::Copy([BitConverter]::GetBytes($dllChars), 0, $outBytes, $opt + 70, 2)
# 校验和清零
[Array]::Copy([BitConverter]::GetBytes([uint32]0), 0, $outBytes, $opt + 64, 4)

[System.IO.File]::WriteAllBytes($Out, $outBytes)
"已写出: $Out ({0} 字节, 折叠为文件布局)" -f $outBytes.Length | Write-Host
