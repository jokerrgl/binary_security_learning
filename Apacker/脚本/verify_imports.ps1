# verify_imports.ps1 — 校验我们重建的导入表: 每个 ILT 名字是否真的存在于对应 DLL 的导出里
param([Parameter(Mandatory=$true)][string]$Exe)

$f = [System.IO.File]::ReadAllBytes($Exe)
$lf = [BitConverter]::ToInt32($f, 0x3C); $opt = $lf + 24
$nsec = [BitConverter]::ToUInt16($f, $lf + 6)
$secTab = $opt + [BitConverter]::ToUInt16($f, $lf + 20)
$dd = $opt + 112

$secs = @()
for ($i = 0; $i -lt $nsec; $i++) {
  $o = $secTab + $i*40
  $secs += [pscustomobject]@{
    VA = [BitConverter]::ToUInt32($f, $o+12); VS = [BitConverter]::ToUInt32($f, $o+8); RS = [BitConverter]::ToUInt32($f, $o+16); RP = [BitConverter]::ToUInt32($f, $o+20)
  }
}
function FileOff([uint32]$rva) {
  foreach ($s in $secs) {
    if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VS, $s.RS))) { return [int]($s.RP + ($rva - $s.VA)) }
  }
  return -1
}
function ReadStr([uint32]$rva) {
  $o = FileOff $rva
  if ($o -lt 0 -or $o -ge $f.Length) { return $null }
  $e = $o; while ($e -lt $f.Length -and $f[$e] -ne 0) { $e++ }
  return [System.Text.Encoding]::ASCII.GetString($f, $o, $e - $o)
}

# DLL 导出名集合
$cache = @{}
function ExportsOf([string]$dll) {
  if ($cache.ContainsKey($dll)) { return $cache[$dll] }
  $hits = @()
  foreach ($dir in @("C:\Windows\System32", "C:\Windows\SysWOW64")) {
    $p = Join-Path $dir $dll
    if (-not (Test-Path $p)) { $p = Join-Path $dir ($dll + ".dll") }
    if (Test-Path $p) { $hits += $p; break }
  }
  $set = New-Object 'System.Collections.Generic.HashSet[string]'
  if ($hits.Count -gt 0) {
    $b = [System.IO.File]::ReadAllBytes($hits[0])
    $l2 = [BitConverter]::ToInt32($b, 0x3C); $o2 = $l2 + 24
    $mg = [BitConverter]::ToUInt16($b, $o2); $dd2 = if ($mg -eq 0x20B) { $o2 + 112 } else { $o2 + 96 }
    $ns = [BitConverter]::ToUInt16($b, $l2 + 6); $st = $o2 + [BitConverter]::ToUInt16($b, $l2 + 20)
    $ss = @()
    for ($i = 0; $i -lt $ns; $i++) {
      $o3 = $st + $i*40
      $ss += [pscustomobject]@{ VA=[BitConverter]::ToUInt32($b,$o3+12); VS=[BitConverter]::ToUInt32($b,$o3+8); RP=[BitConverter]::ToUInt32($b,$o3+20) }
    }
    $f2 = { param($rva) foreach ($s in $ss) { if ($rva -ge $s.VA -and $rva -lt ($s.VA + [Math]::Max($s.VS,1))) { return $s.RP + ($rva - $s.VA) } } return -1 }
    $eRva = [BitConverter]::ToUInt32($b, $dd2)
    if ($eRva -ne 0) {
      $eo = & $f2 $eRva
      if ($eo -ge 0) {
        $n = [BitConverter]::ToUInt32($b, $eo+24); $an = [BitConverter]::ToUInt32($b, $eo+32)
        $no = & $f2 $an
        for ($i = 0; $i -lt $n; $i++) {
          $s2 = & $f2 ([BitConverter]::ToUInt32($b, $no + $i*4))
          if ($s2 -lt 0) { continue }
          $e2 = $s2; while ($b[$e2] -ne 0) { $e2++ }
          [void]$set.Add([System.Text.Encoding]::ASCII.GetString($b, $s2, $e2 - $s2))
        }
      }
    }
  } else { return $null }
  $cache[$dll] = $set
  return $set
}

$impRva = [BitConverter]::ToUInt32($f, $dd + 8)
$impSize = [BitConverter]::ToUInt32($f, $dd + 12)
$descOff = FileOff $impRva
"Import RVA=0x{0:X} Size=0x{1:X} 文件偏移=0x{2:X}" -f $impRva, $impSize, $descOff | Write-Host
$bad = 0; $total = 0
for ($i = 0; $i -lt [int]($impSize / 20); $i++) {
  $o = $descOff + $i*20
  $oft = [BitConverter]::ToUInt32($f, $o); $nmRva = [BitConverter]::ToUInt32($f, $o+12); $ft = [BitConverter]::ToUInt32($f, $o+16)
  if ($oft -eq 0 -and $nmRva -eq 0) { break }
  $dll = ReadStr $nmRva
  $exp = ExportsOf $dll
  $ilt = FileOff $oft
  $names = @()
  for ($k = 0; ; $k++) {
    $v = [BitConverter]::ToUInt64($f, $ilt + $k*8)
    if ($v -eq 0) { break }
    $hr = [uint32]($v -band 0x7FFFFFFF)
    $names += (ReadStr ($hr + 2))
  }
  $missing = @()
  foreach ($n in $names) {
    $total++
    if ($null -eq $exp) { $missing += "$n(模块未找到)"; continue }
    if (-not $exp.Contains($n)) { $missing += $n }
  }
  if ($missing.Count -gt 0) {
    $bad += $missing.Count
    "  [{0}] {1} FT=0x{2:X5} 共{3}项, 缺失: {4}" -f $i, $dll, $ft, $names.Count, ($missing -join ', ') | Write-Host
  }
}
"校验完成: 共 {0} 个导入名, 缺失 {1} 个" -f $total, $bad | Write-Host
