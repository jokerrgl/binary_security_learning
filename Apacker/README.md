# Apacker 壳分析与脱壳机

本目录是对 `Campus_Network_learning.exe` / `Campus_Network_Repair.exe` 两个样本（均由 Apacker 加壳）的完整分析成果，以及一个可复用的静态脱壳机。

## 一句话结论

- **壳的加密层已彻底脱掉**：AES-256-CTR 密钥/IV 完全复原，`.text` 57 页全部解出，并与壳运行时自己解过的 50+ 页逐字节一致（差异 0 字节）。
- **导入混淆已还原**：115 个导入（模块+函数名）全部反查出来，对着系统 DLL 导出表校验 0 缺失。
- **真实 OEP 已定位**：`0x11B40`（`mainCRTStartup`）。
- **脱壳机可用且通用**：对第二个样本 `Campus_Network_Repair.exe` 同样自动识别（OEP=0x6840、34 页、88 导入）。
- **还差一步**：把桩完全去掉后，Windows 加载器不肯回填原本位于 `.rdata` 起始的 IAT，所以“无桩可运行版”尚未完成；现有可运行版是“代码明文 + 桩只负责解析导入”。

## 目录结构

```
Apacker壳分析与脱壳机\
├── README.md                     ← 本文件
├── 报告\
│   ├── 01_壳技术分析报告.md       ← 主报告：加密/配置/执行流/反调试/强度评价
│   ├── 02_PDB符号与工程结构.md    ← 从 PDB 恢复的源码结构、符号、stub 位置
│   ├── 03_样本参数速查.md         ← 两个样本的全部关键参数
│   └── 04_实验记录与结论.md       ← 做过哪些实验、哪些成立、未解问题
├── 脱壳机\
│   ├── apk_unpack.ps1            ← 静态脱壳机（不运行样本）
│   ├── 用法.md
│   └── 自检结果.txt              ← 两个样本的实测输出
├── 产物\
│   ├── Campus_Network_learning.text.bin          解密后的 .text（231,052 字节）
│   ├── Campus_Network_learning.unpacked.exe      脱壳机输出（EP=OEP、全页明文）
│   ├── Campus_Network_learning.report.json       结构报告（含每页 CRC 记录）
│   ├── Campus_Network_Repair.text.bin            Repair 样本的 .text
│   ├── Campus_Network_Repair.unpacked.exe
│   ├── Campus_Network_Repair.report.json
│   ├── Campus_Network_learning.manual_rebuild_no_stub.exe  手工重建的无桩版（可静态分析，不宜直接运行）
│   └── Campus_Network_learning.plaincode_runnable.exe      代码明文但含桩（可运行）
├── 脚本\                          ← 过程中用到的原始脚本（解密/内存dump/IAT解析/重建/校验）
├── 中间产物\                      ← 运行时内存镜像、模块表、IAT 解析、实验用临时文件
└── 样本\
    ├── Campus_Network_learning.exe
    ├── Campus_Network_Repair.exe
    └── key.txt
```

## 脱壳机怎么用

```powershell
# 1) 直接在当前会话里跑（绕过执行策略）
$sb = [scriptblock]::Create((Get-Content -Raw -Encoding UTF8 .\apk_unpack.ps1))
& $sb -InputFile "样本\Campus_Network_learning.exe" -OutDir "产物"

# 2) 或者先放开策略再按脚本调用
Set-ExecutionPolicy -Scope Process Bypass
.\apk_unpack.ps1 -InputFile <被壳的exe> -OutDir <输出目录>
```

会输出三件东西：`*.unpacked.exe`（EP 已改回原始 OEP、所有加密页明文）、`*.text.bin`、`*.report.json`。

## 关键结论速览

| 项目 | 结果 |
|---|---|
| 壳类型 | 自研 x64 PE 加密壳（Qt6+LIEF，`apk::` 命名空间），非商业保护器 |
| 加密 | AES-256-CTR，页粒度 0x1000，IV=`[key值][0][页VA][0]`，每页独立 |
| 密钥派生 | `key[i] = ~T1[i] ^ T2[i] ^ k0 ^ k1`（T1/T2 在桩节 +0x38/+0x58，k0/k1 来自头部 4 字节 key 值） |
| 两段结构 | `AKPH`(桩头) → 解出 `AKPC`(运行配置) → 惰性页解密 → 跳 OEP |
| 反调试 | 守护线程循环：页 CRC32 完整性 + 全线程 Dr0~Dr3 扫描 + PEB/时序/窗口等检测 + 分级响应（含 `int 0x29` __fastfail） |
| 反 dump | 未执行页保持密文；对“命中调试寄存器的页”故意不解密 |
| 导入 | 默认清空导入表，桩按“哈希表→GetProcAddress”重建；可用 `obfuscate_imports=0` 保留 |
| 强度 | 中：能挡"随手 x64dbg+Scylla"，挡不住按页复现密钥的静态脱壳 |

## 注意

- 两个样本程序**自身要求管理员权限**（非提权运行只会打印“请以管理员身份运行此程序”后退出），所以即使完全脱壳，非提权双击也不会真正运行。
- `产物\*.unpacked.exe` 用于 **IDA/Ghidra 静态分析**；直接运行会因 IAT 为空而崩（原因见 `报告\04`）。
- 中间产物里的内存镜像（`main_image.bin`）来自本机一次运行，含当时模块基址，只作取证参考。
