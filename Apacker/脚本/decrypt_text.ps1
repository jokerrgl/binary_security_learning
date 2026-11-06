# decrypt_text.ps1 — 复现壳的逐页解密: AES-256-CTR
#   key[i] = (~T1[i]) ^ T2[i] ^ k0 ^ k1     (T1 = .AXJvbGt+0x38, T2 = .AXJvbGt+0x58, 各 32 字节)
#   IV  = [4字节 ctx[0xF] = 头里的 key 值] [00000000] [页VA 小端] [00000000]
# 入口: 描述符 = 内存镜像 0x63000("AKPC"), count = u32@+0x24, 表 = 0x63000 + u32@+0x3C, 步长 0x14
# 用法: .\decrypt_text.ps1 -Orig ...\Campus_Network_learning.exe -Image ...\main_image.bin -Out ...\text_dec.bin

param(
  [Parameter(Mandatory=$true)][string]$Orig,
  [Parameter(Mandatory=$true)][string]$Image,
  [Parameter(Mandatory=$true)][string]$Out
)

$ErrorActionPreference = 'Stop'
$o = [System.IO.File]::ReadAllBytes($Orig)
$m = [System.IO.File]::ReadAllBytes($Image)

# .text: file raw 0x400 / VA 0x1000 ; .AXJvbGt: file raw 0x52E00 / VA 0x58000
$TEXTRaw = 0x400
$AXRaw   = 0x52E00
$AXVA    = 0x58000

$T1 = $o[($AXRaw+0x38)..($AXRaw+0x57)]
$T2 = $o[($AXRaw+0x58)..($AXRaw+0x77)]
$kv = [BitConverter]::ToUInt32($m, 0x58030)          # ctx[0xF]
$k0 = [byte]($kv -band 0xFF)
$k1 = [byte](($kv -shr 8) -band 0xFF)
"key 值 = 0x{0:X8}  k0=0x{1:X2} k1=0x{2:X2}" -f $kv,$k0,$k1 | Write-Host

$key = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $key[$i] = [byte](0xFF -bxor $T1[$i] -bxor $T2[$i] -bxor $k0 -bxor $k1) }
"派生密钥 = " + (($key | ForEach-Object { $_.ToString('X2') }) -join ' ') | Write-Host

$count = [BitConverter]::ToUInt32($m, 0x63000 + 0x24)
$tabOff = 0x63000 + [BitConverter]::ToUInt32($m, 0x63000 + 0x3C)
"描述符: count={0}  表@0x{1:X}" -f $count, $tabOff | Write-Host

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = 'ECB'; $aes.Padding = 'None'; $aes.Key = $key
$enc = $aes.CreateEncryptor()

function DecryptPage([uint32]$va, [int]$size, [byte]$k0v, [byte]$k1v, [byte]$k2v, [byte]$k3v) {
  # 密文来源: 原始文件 .text
  $fo = $TEXTRaw + ([int64]$va - 0x1000)
  $ct = New-Object byte[] $size
  [Array]::Copy($o, $fo, $ct, 0, $size)
  # CTR: 逐 16 字节块
  $iv = New-Object byte[] 16
  $iv[0] = $k0v; $iv[1] = $k1v; $iv[2] = $k2v; $iv[3] = $k3v
  $iv[8] = [byte]($va -band 0xFF); $iv[9] = [byte](($va -shr 8) -band 0xFF)
  $iv[10] = [byte](($va -shr 16) -band 0xFF); $iv[11] = [byte](($va -shr 24) -band 0xFF)
  $pt = New-Object byte[] $size
  $cblock = New-Object byte[] 16
  [Array]::Copy($iv, $cblock, 16)
  $ks = New-Object byte[] 16
  $pos = 0
  while ($pos -lt $size) {
    $enc.TransformBlock($cblock, 0, 16, $ks, 0) | Out-Null
    $n = [Math]::Min(16, $size - $pos)
    for ($i = 0; $i -lt $n; $i++) { $pt[$pos+$i] = $ct[$pos+$i] -bxor $ks[$i] }
    # 128-bit 大端 +1
    for ($j = 15; $j -ge 0; $j--) { $cblock[$j] = [byte](($cblock[$j] + 1) -band 0xFF); if ($cblock[$j] -ne 0) { break } }
    $pos += 16
  }
  return $pt
}

$b0 = [byte]($kv -band 0xFF); $b1 = [byte](($kv -shr 8) -band 0xFF)
$b2 = [byte](($kv -shr 16) -band 0xFF); $b3 = [byte](($kv -shr 24) -band 0xFF)

$total = 0
$result = @{}
$bad = @()
for ($i = 0; $i -lt $count; $i++) {
  $e = $tabOff + $i*0x14
  $va = [BitConverter]::ToUInt32($m, $e)
  $size = [BitConverter]::ToUInt16($m, $e + 6)
  if ($size -eq 0) { continue }
  if ($va -lt 0x1000 -or ($va + $size) -gt 0x3A000) { $bad += ('entry {0}: VA=0x{1:X} size=0x{2:X} 超出 .text' -f $i,$va,$size); continue }
  $pt = DecryptPage $va $size $b0 $b1 $b2 $b3
  $result[$va] = $pt
  $total += $size
  # 与内存镜像对比(该页若已解密)
  $mem = $m[$va .. ($va + $size - 1)]
  $same = $true
  for ($k = 0; $k -lt $size; $k++) { if ($mem[$k] -ne $pt[$k]) { $same = $false; break } }
  if ($i -lt 3 -or $same) {
    "entry[{0}] VA=0x{1:X5} size=0x{2:X} 与内存已解密页一致={3} 首16: {4}" -f $i,$va,$size,$same,(($pt[0..15] | ForEach-Object { $_.ToString('X2') }) -join ' ') | Write-Host
  }
}
$bad | ForEach-Object { "警告: $_" | Write-Host }
"共解密 {0} 个条目, 合计 0x{1:X} 字节" -f $result.Count, $total | Write-Host

# 按 VA 拼回整段 .text (0x1000 .. 0x3A000)
$textSize = 0x39000
$buf = New-Object byte[] $textSize
# 先填原始密文(未覆盖的页保持原样)
[Array]::Copy($o, $TEXTRaw, $buf, 0, [Math]::Min($textSize, $o.Length - $TEXTRaw))
foreach ($va in $result.Keys) {
  $pt = $result[$va]
  [Array]::Copy($pt, 0, $buf, [int]($va - 0x1000), $pt.Length)
}
[System.IO.File]::WriteAllBytes($Out, $buf)
"已写出解密的 .text: $Out (0x{0:X})" -f $textSize | Write-Host
"解密后 .text 首 64 字节: " + (($buf[0..63] | ForEach-Object { $_.ToString('X2') }) -join ' ')

# 熵检查
function Ent([byte[]]$d) { $c = New-Object 'int[]' 256; foreach ($x in $d) { $c[$x]++ }; $H = 0.0; foreach ($n in $c) { if ($n -gt 0) { $q = $n / $d.Length; $H -= $q * [Math]::Log($q, 2) } }; [Math]::Round($H, 3) }
"解密后整体熵 = " + (Ent $buf)
