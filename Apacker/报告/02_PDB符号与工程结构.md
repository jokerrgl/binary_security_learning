# 从 PDB 恢复的工程结构

> 来源：`D:\sec\Tools\Tool_List\apacker_gui\apacker_cli.pdb`（11 MB，MSVC 调试符号）
> 结论先说：**目录里没有源码文件**（只有 .dll/.ini/.exe/.ilk/.pdb），但 PDB 里有
> **完整源文件清单 + 163 个 `apk::` 符号 + 内部数据结构名**，等于"源码地图 + 全部函数签名"。
> PDB 不含源码正文。

## 1. 源文件清单（13 个）

```
E:\ai_project\dsh\Apacker\src\cli\main.cpp
E:\ai_project\dsh\Apacker\src\core\pack_options.cpp
E:\ai_project\dsh\Apacker\src\core\pack_options.hpp
E:\ai_project\dsh\Apacker\src\core\packer.cpp
E:\ai_project\dsh\Apacker\src\core\packer.hpp
E:\ai_project\dsh\Apacker\src\core\pe_utils.cpp
E:\ai_project\dsh\Apacker\src\core\pe_utils.hpp
E:\ai_project\dsh\Apacker\src\core\stub_blob.hpp
E:\ai_project\dsh\Apacker\src\core\verify.cpp
E:\ai_project\dsh\Apacker\src\shared\aes256.hpp
E:\ai_project\dsh\Apacker\src\shared\apk_layout.h
E:\ai_project\dsh\Apacker\src\shared\crc32.hpp
E:\ai_project\dsh\Apacker\src\shared\sha256.hpp
```

编译参数里带 `-std:c++20 -O2 -MD -Zi -EHsc`，说明是 MSVC 2022（14.44.35207）+ CMake 构建。

## 2. 内部数据模型（`packer.cpp` 匿名命名空间）

| 结构 | 推测用途 |
|---|---|
| `SectionInfo` | 参与加密的节描述（VA/VSize/RawSize/Characteristics） |
| `PageInfo` | 页表条目（页VA、长度、密文CRC、明文CRC） |
| `ImportDllInfo` / `ImportEntryInfo` | 导入 DLL 与具体导入项 |
| `RelocEntry` | 重定位项 |
| `PackOptions` / `PackResult` / `PackStats` / `VerifyReport` | 选项/结果/统计/校验报告 |
| `IProgress` | 进度回调接口（GUI 用） |

## 3. 主要函数/类（节选，共 163 个符号）

**加密原语**
```
apk::aes256_ctr_xor(key, iv, data, len)      — CTR 加解密
apk::aes256_ctr_nonce(u32, u32, out16)       — 生成 16 字节 IV
apk::Aes256::init / encrypt_block
apk::aes_gmul                                — GF(2^8) 乘
apk::Sha256::update / final / block / sha256_rotr
apk::HmacSha256::init / update / final
```

**PE 操作（基于 LIEF）**
```
apk::SectionForRva(Binary&, rva)
apk::ReadRva / WriteRva / ZeroRva / ZeroUntilZero
apk::AlignUp
apk::PackFile(options, progress)             — 主流程
apk::VerifyFile(path, verbose)               — 输出自检
apk::LoadProfile / SaveProfile
apk::kStubBlobData / kStubBlobSize / kStubEntryOffset / kStubHeaderOffset
```

**其它**：`ParseInt`、`ToAcp/FromAcp/ToUtf8/FromUtf8`、`PackResult` 构造/析构、`Cancelled` 异常等。

## 4. 桩（stub）的位置

- PDB 显示桩是**构建期生成的字节数组**：`build\generated\stub_blob.cpp`（由 `apk_stub_extract <apkr_stub.dll> <out.cpp>` 生成）。
- 桩以明文嵌在 `apacker_cli.exe` **文件偏移 `0x6AD50`，长度 `0xA73D`**，开头即 `ApkStubHeader`：

```
+0x00  01 00 00 00            ; version = 1
+0x10  "AKPH" 01 00 00 00     ; 魔数 + 版本
+0x18  ...                    ; 打包时填入 stub 节 VA / stage2 VA / 长度 / key 值
```

- 这段 blob 与样本里 `.AXJvbGt` 节**逐字节同源**（相对偏移完全一致），所以所有 Apacker 产物共用同一份桩代码。
- 注意：目录里**没有真正的 `apkr_stub.dll`**。我把 blob 导出后交给 `apk_stub_extract`，它报
  `cannot parse ... as PE` —— 该工具要求输入是真 PE 文件，而这里的桩只有节区数据（无 MZ/PE 头）。

## 5. 能恢复 / 不能恢复

| 能 | 不能 |
|---|---|
| 源文件目录树与文件名 | 源码正文（PDB 只存路径+行号） |
| 全部函数/类/结构体名字与签名 | 函数体实现（需反编译，见主报告） |
| 编译参数、工具链版本、作者本机路径 | 注释、宏定义 |
| 调试时可按符号对应到地址（符号化调试） | —— |

> 提示：这类 PDB 对攻击方等于"带注释的地图"。商业壳不会发布自己的 PDB；
> 这里之所以能拿到，是因为它是自研工具链的构建产物。
