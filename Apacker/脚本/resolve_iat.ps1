# resolve_iat.ps1 — 把内存镜像里的 IAT 指针解析成 (模块, 导出名)，输出 JSON
param(
  [Parameter(Mandatory=$true)][string]$Image,
  [Parameter(Mandatory=$true)][string]$ModulesJson,
  [Parameter(Mandatory=$true)][string]$OutJson,
  [int]$Start = 0x3A000,
  [int]$End = 0x3A500
)
$ErrorActionPreference = 'Stop'
$m = [System.IO.File]::ReadAllBytes($Image)
$mods = Get-Content -Raw -Encoding UTF8 $ModulesJson | ConvertFrom-Json

# 解析某个模块文件的导出表: RVA -> Name
function GetExports([string]$path) {
  $d = @{}
  if (-not (Test-Path $path)) { return $d }
  $b = [System.IO.File]::ReadAllBytes($path)
  $lf = [BitConverter]::ToInt32($b, 0x3C)
  if ([BitConverter]::ToUInt32($b, $lf) -ne 0x4550) { return $d }
  $opt = $lf + 24
  $magic = [BitConverter]::ToUInt16($b, $opt)
  $ddBase = if ($magic -eq 0x20B) { $opt + 112 } else { $opt + 96 }
  $nsec = [BitConverter]::ToUInt16($b, $lf + 6)
  $st = $opt + [BitConverter]::ToUInt16($b, $lf + 20)
  $secs = @()
  for ($i = 0; $i -lt $nsec; $i++) {
    $o = $st + $i*40
    $secs += [pscustomobject]@{
      VA = [BitConverter]::ToUInt32($b, $o+12); VS = [BitConverter]::ToUInt32($b, $o+8); RP = [BitConverter]::ToUInt32($b, $o+20)
    }
  }
  function R2O([uint32]$rva) {
    foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VS, 1))) { return $s.RP + ($rva - $s.VA) } }
    return -1
  }
  $expRva = [BitConverter]::ToUInt32($b, $ddBase)
  if ($expRva -eq 0) { return $d }
  $eo = R2O $expRva
  if ($eo -lt 0) { return $d }
  $nNames = [BitConverter]::ToUInt32($b, $eo+24)
  $af = [BitConverter]::ToUInt32($b, $eo+28)
  $an = [BitConverter]::ToUInt32($b, $eo+32)
  $ao = [BitConverter]::ToUInt32($b, $eo+36)
  $no = R2O $an; $fo = R2O $af; $oo = R2O $ao
  if ($no -lt 0 -or $fo -lt 0 -or $oo -lt 0) { return $d }
  for ($i = 0; $i -lt $nNames; $i++) {
    $nr = [BitConverter]::ToUInt32($b, $no + $i*4)
    $s = R2O $nr
    if ($s -lt 0) { continue }
    $e = $s; while ($b[$e] -ne 0 -and ($e - $s) -lt 256) { $e++ }
    $nm = [System.Text.Encoding]::ASCII.GetString($b, $s, $e - $s)
    $ord = [BitConverter]::ToUInt16($b, $oo + $i*2)
    $fr = [BitConverter]::ToUInt32($b, $fo + $ord*4)
    if (-not $d.ContainsKey([uint32]$fr)) { $d[[uint32]$fr] = $nm } else { $d[[uint32]$fr] = $d[[uint32]$fr] }
  }
  return $d
}

$ranges = @()
foreach ($x in $mods) {
  $b = [Convert]::ToUInt64($x.base, 16)
  $ranges += [pscustomobject]@{ Name = $x.name; Base = $b; End = ($b + [Convert]::ToUInt64($x.size, 16)); Path = $x.path }
}

# 模块导出缓存(按路径)
$cache = @{}
$rows = @()
for ($off = $Start; $off -lt $End; $off += 8) {
  $v = [BitConverter]::ToUInt64($m, $off)
  if ($v -eq 0) { $rows += [pscustomobject]@{ Off = $off; Module = $null; RVA = $null; Name = $null }; continue }
  $hit = $null
  foreach ($r in $ranges) { if ($v -ge $r.Base -and $v -lt $r.End) { $hit = $r; break } }
  if (-not $hit) { $rows += [pscustomobject]@{ Off = $off; Module = '?'; RVA = ('0x{0:X}' -f $v); Name = '?' }; continue }
  $rva = $v - $hit.Base
  if (-not $cache.ContainsKey($hit.Path)) { $cache[$hit.Path] = GetExports $hit.Path }
  $exp = $cache[$hit.Path]
  $nm = if ($exp.ContainsKey([uint32]$rva)) { $exp[[uint32]$rva] } else { $null }
  $rows += [pscustomobject]@{ Off = $off; Module = $hit.Name; RVA = ('0x{0:X}' -f $rva); Name = $nm }
}

$rows | Where-Object { $_.Module -ne $null } | ForEach-Object {
  "  0x{0:X5}  {1,-28} {2,-12} {3}" -f $_.Off, $_.Module, $_.RVA, $_.Name
}
"槽位总数={0}, 已解析={1}, 未解析={2}" -f $rows.Count, ($rows | Where-Object { $_.Name }).Count, ($rows | Where-Object { $_.Module -and -not $_.Name }).Count
$rows | ConvertTo-Json -Depth 3 | Set-Content $OutJson -Encoding UTF8
