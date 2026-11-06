# build_unpacked.ps1 — 组装脱壳后的 PE
#   1) 用解密后的 .text 覆盖原密文
#   2) 追加 .idata: 按运行时 IAT 重建导入描述符/ILT/名字
#   3) 入口点改为原始 OEP, 关闭 ASLR(保证自引用指针有效)
param(
  [Parameter(Mandatory=$true)][string]$Orig,
  [Parameter(Mandatory=$true)][string]$TextDec,
  [Parameter(Mandatory=$true)][string]$IatJson,
  [Parameter(Mandatory=$true)][string]$Out,
  [string]$Oep = "0x1020",
  [uint32]$IatStart = 0x3A000,
  [uint32]$IatEnd   = 0x3A400
)
$ErrorActionPreference = 'Stop'

$f = [System.IO.File]::ReadAllBytes($Orig)
$dec = [System.IO.File]::ReadAllBytes($TextDec)
$iat = Get-Content -Raw -Encoding UTF8 $IatJson | ConvertFrom-Json

# ---- 头部基本量
$lf = [BitConverter]::ToInt32($f, 0x3C)
$opt = $lf + 24
$magic = [BitConverter]::ToUInt16($f, $opt)
$nsec = [BitConverter]::ToUInt16($f, $lf + 6)
$optSize = [BitConverter]::ToUInt16($f, $lf + 20)   # 注意: lf 指向 "PE\0\0", 文件头从 lf+4 开始
$secTab = $opt + $optSize
$ddBase = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
$sizeOfImage = [BitConverter]::ToUInt32($f, $opt + 56)
$fileAlign = [BitConverter]::ToUInt32($f, $opt + 36)
$sectAlign = [BitConverter]::ToUInt32($f, $opt + 32)

function Align([uint32]$v, [uint32]$a) { [uint32]([Math]::Ceiling([double]$v / $a) * $a) }

# ---- 1. 收集要重建的导入槽位(跳过指向自身/空/未解析的)
$slots = @()
foreach ($r in $iat) {
  $off = [uint32]$r.Off
  if ($off -lt $IatStart -or $off -ge $IatEnd) { continue }
  if (-not $r.Module -or -not $r.Name) { continue }
  if ($r.Module -eq 'Campus_Network_learning.exe') { continue }
  $slots += [pscustomobject]@{ Off = $off; Module = $r.Module; Name = $r.Name }
}
$slots = $slots | Sort-Object Off
"参与重建的导入槽位: {0} 个" -f $slots.Count | Write-Host

# ---- 2. 把槽位按"同一模块连续"切成 run(每个 run 一个描述符)
$runs = @()
$cur = $null
foreach ($s in $slots) {
  if ($cur -and $cur.Module -eq $s.Module -and ($cur.End + 8) -eq $s.Off) {
    $cur.Slots += $s; $cur.End = $s.Off
  } else {
    if ($cur) { $runs += $cur }
    $cur = [pscustomobject]@{ Module = $s.Module; Start = $s.Off; End = $s.Off; Slots = @($s) }
  }
}
if ($cur) { $runs += $cur }
"描述符数量(按模块连续段切分): {0}" -f $runs.Count | Write-Host

# ---- 3. 生成 .idata 内容
$ilts = @()          # {Run, Rva}
$hnTable = @()       # {Name, Rva}
$dllNames = @()      # {Name, Rva}
$body = New-Object System.Collections.Generic.List[byte]

# 预计算布局: descriptors | ILTs | hint/name | dllname
$descSize = ($runs.Count + 1) * 20
$iltOffsets = @{}
$sumIlt = 0
foreach ($r in $runs) { $iltOffsets[$r] = $sumIlt; $sumIlt += ($r.Slots.Count + 1) * 8 }

$baseRva = Align ($sizeOfImage) $sectAlign     # 新节 VA
$cursor = [uint32]$descSize
$iltBase = [uint32]$cursor
$cursor += [uint32]$sumIlt

# hint/name 表
$hnRva = @{}
foreach ($s in $slots) {
  $key = $s.Name
  if (-not $hnRva.ContainsKey($key)) {
    $hnRva[$key] = [uint32]($baseRva + $cursor)
    $cursor += [uint32](2 + $key.Length + 1)
    $cursor = [uint32](Align $cursor 2)
  }
}
# dll 名字表
$dllRva = @{}
foreach ($r in $runs) {
  if (-not $dllRva.ContainsKey($r.Module)) {
    $dllRva[$r.Module] = [uint32]($baseRva + $cursor)
    $cursor += [uint32]($r.Module.Length + 1)
  }
}
$sectionSize = Align $cursor $sectAlign
"新 .idata: VA=0x{0:X} 大小=0x{1:X} (descriptors=0x{2:X}, ilt=0x{3:X})" -f $baseRva, $sectionSize, $descSize, $sumIlt | Write-Host

$secBuf = New-Object byte[] $sectionSize
function W32([int]$o, [uint32]$v) { [Array]::Copy([BitConverter]::GetBytes($v), 0, $secBuf, $o, 4) }
function W64([int]$o, [uint64]$v) { [Array]::Copy([BitConverter]::GetBytes($v), 0, $secBuf, $o, 8) }

# 描述符
$di = 0
for ($i = 0; $i -lt $runs.Count; $i++) {
  $r = $runs[$i]
  $o = $i * 20
  W32 ($o + 0) ([uint32]($baseRva + $iltBase + $iltOffsets[$r]))     # OriginalFirstThunk
  W32 ($o + 4) 0                                                     # TimeDateStamp
  W32 ($o + 8) 0                                                     # ForwarderChain
  W32 ($o + 12) $dllRva[$r.Module]                                   # Name
  W32 ($o + 16) ([uint32]$r.Start)                                   # FirstThunk (必须是 RVA)
  $di = $o
}
# 结束描述符保持全 0

# ILT
foreach ($r in $runs) {
  $o = $iltBase + $iltOffsets[$r]
  foreach ($s in $r.Slots) {
    W64 $o ([uint64]$hnRva[$s.Name])
    $o += 8
  }
  W64 $o 0
}
# hint/name
foreach ($k in $hnRva.Keys) {
  $o = [int]($hnRva[$k] - $baseRva)
  [Array]::Copy([BitConverter]::GetBytes([uint16]0), 0, $secBuf, $o, 2)
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($k)
  [Array]::Copy($bytes, 0, $secBuf, $o + 2, $bytes.Length)
}
# dll 名
foreach ($k in $dllRva.Keys) {
  $o = [int]($dllRva[$k] - $baseRva)
  $bytes = [System.Text.Encoding]::ASCII.GetBytes($k)
  [Array]::Copy($bytes, 0, $secBuf, $o, $bytes.Length)
}

# ---- 4. 写文件 (用 MemoryStream, 避免大数组分配问题)
$lastSec = $secTab + ($nsec - 1) * 40
$lastRawEnd = [uint32]([BitConverter]::ToUInt32($f, $lastSec + 20) + [BitConverter]::ToUInt32($f, $lastSec + 16))
$newRaw = Align $lastRawEnd $fileAlign
$total = [int64]$newRaw + [int64]$sectionSize

$ms = New-Object System.IO.MemoryStream
$ms.SetLength($total)
function P([int]$off, [byte[]]$bytes) { $ms.Position = $off; $ms.Write($bytes, 0, $bytes.Length) }
function P32([int]$off, [uint32]$v) { P $off ([BitConverter]::GetBytes($v)) }
function P16([int]$off, [uint16]$v) { P $off ([BitConverter]::GetBytes($v)) }

P 0 $f

# 覆盖 .text (raw 0x400, 大小 0x38800)
$textRaw = 0x400
$textRawSize = 0x38800
$n = [Math]::Min($dec.Length, $textRawSize)
$decTrim = New-Object byte[] $n
[Array]::Copy($dec, 0, $decTrim, 0, $n)
P $textRaw $decTrim
"已写入解密 .text: 0x{0:X} 字节" -f $n | Write-Host

# 追加节数据
P ([int]$newRaw) $secBuf

# 新节表项
$nsOff = $secTab + $nsec * 40
$nameBytes = [System.Text.Encoding]::ASCII.GetBytes(".idata")
$nmPad = New-Object byte[] 8
[Array]::Copy($nameBytes, 0, $nmPad, 0, $nameBytes.Length)
P $nsOff $nmPad
P32 ($nsOff + 8)  ([uint32]$sectionSize)   # VirtualSize
P32 ($nsOff + 12) ([uint32]$baseRva)       # VirtualAddress
P32 ($nsOff + 16) ([uint32]$sectionSize)   # SizeOfRawData
P32 ($nsOff + 20) ([uint32]$newRaw)        # PointerToRawData
P32 ($nsOff + 36) ([uint32]3221225536)     # 0xC0000040 RW

# 头字段
P16 ($lf + 6) ([uint16]($nsec + 1))
P32 ($opt + 56) ([uint32]($baseRva + $sectionSize))   # SizeOfImage
$oepV = [Convert]::ToUInt32($Oep, 16)
P32 ($opt + 16) $oepV                                 # AddressOfEntryPoint
P32 ($opt + 36) ([uint32]$fileAlign)

# 数据目录: Import / IAT
P32 ($ddBase + 8)   ([uint32]$baseRva)                        # Import RVA
P32 ($ddBase + 12)  ([uint32]($runs.Count * 20))              # Import Size
P32 ($ddBase + 96)  ([uint32]$runs[0].Start)                  # IAT RVA (镜像内 RVA, 不要再加 baseRva)
P32 ($ddBase + 100) ([uint32]($IatEnd - $IatStart))           # IAT Size

# 关闭 ASLR + 校验和清零
$ms.Position = $opt + 70
$b2 = New-Object byte[] 2
[void]$ms.Read($b2, 0, 2)
$dllc = [uint16]([BitConverter]::ToUInt16($b2, 0) -band (-bnot 0x40))
P16 ($opt + 70) $dllc
P32 ($opt + 64) ([uint32]0)

# 修补"指向自身模块"的指针槽(CFG guard 函数指针等): 运行时是绝对 VA, 这里按首选基址写回
function FileOffForRva([uint32]$rva) {
  $st = $secTab
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $st + $i*40
    $va = [BitConverter]::ToUInt32($f, $o+12); $vs = [BitConverter]::ToUInt32($f, $o+8); $rp = [BitConverter]::ToUInt32($f, $o+20)
    if ($rva -ge $va -and $rva -lt ($va + [Math]::Max($vs,1))) { return [int]($rp + ($rva - $va)) }
  }
  return -1
}
$imgBase = [BitConverter]::ToUInt64($f, $opt + 24)
$selfPatched = 0
foreach ($r in $iat) {
  if (-not $r.Module) { continue }
  if ($r.Module -notlike 'Campus_Network_learning*') { continue }
  $rva = [Convert]::ToUInt32($r.RVA, 16)
  $fo = FileOffForRva ([uint32]$r.Off)
  if ($fo -lt 0) { continue }
  $val = [uint64]($imgBase + $rva)
  P $fo ([BitConverter]::GetBytes($val))
  $selfPatched++
}
"修补自身指针槽: {0} 个 (基址 0x{1:X})" -f $selfPatched, $imgBase | Write-Host

$ms.Position = 0
$bytes = $ms.ToArray()
[System.IO.File]::WriteAllBytes($Out, $bytes)
"脱壳文件: $Out ({0} 字节)  EP=0x{1:X}  SizeOfImage=0x{2:X}  节数={3}" -f $bytes.Length, $oepV, ($baseRva + $sectionSize), ($nsec + 1) | Write-Host
