<div align="center">

# local-binary-index

**离线 PE 分析引擎，同时是一个 MCP 服务——壳识别、OEP 定位、IAT 重建、反调试补丁、.NET 指纹、dump 修复。**

[![node](https://img.shields.io/badge/node-%E2%89%A520.11-brightgreen)](https://nodejs.org)
[![CI](https://github.com/lingbol088-spec/local-binary-index/actions/workflows/ci.yml/badge.svg)](https://github.com/lingbol088-spec/local-binary-index/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![deps](https://img.shields.io/badge/runtime%20deps-0-success)](package.json)
[![MCP](https://img.shields.io/badge/MCP-stdio-8A2BE2)](https://modelcontextprotocol.io)
[![PRs](https://img.shields.io/badge/PRs-welcome-orange)](CONTRIBUTING.md)

[English](README.md) · [简体中文](README.zh-CN.md) · [工具参考](docs/TOOLS.md) · [免责声明](DISCLAIMER.md)

</div>

> **使用前请先读 [免责声明](DISCLAIMER.md)。** 本项目仅用于**你拥有或已获授权**的二进制分析：安全研究、应急响应、CTF、教学。不附带样本、不执行目标、不联网。

---

## 它是什么

一个零运行时依赖的 PE 分析内核，三种形态：

| 形态 | 你能得到什么 |
|---|---|
| **MCP 服务**（`lbi-mcp`） | 8 个工具，stdio 协议，Codex / Claude Desktop / Cursor 等任意 MCP 客户端可用 |
| **CLI**（`lbi`） | 终端里跑同一套引擎，输出 JSON 或 Markdown |
| **库**（ESM） | `import { analyzeFile } from "local-binary-index"` |

全部是静态分析：读文件、解析、推理。不落地解包、不执行、不出网。

```text
$ lbi zxwn analyze samples/packed.exe --out ./out
判定: packed (1)          主家族: UPX
OEP : 0x0000000000401000  (push 0x401000 ; ret, 得分 100)
IAT : 1 模块 / 3 函数 · 残留描述符 @0x00005500 (USER32.dll, GDI32.dll)
反分析: int 2d @0x00000A10 → 补丁 90 90 · icebp ×4 · TLS 回调 ×1
已写出: out/report.md, out/analysis.json, out/scripts/{x64dbg,gdb,windbg,frida,scylla,patches}
```

---

## 为什么还要一个 PE 工具

大多数"这是什么壳"的回答只有文件名、区段名和一句猜测。真正有用的是一个**计划**：哪个家族、置信度多少、入口转移在哪、导入表去哪了、哪些反调试会咬人、先打什么补丁或断点。

`local-binary-index` 把这份计划作为**带证据的结构化数据**返回：每条信号都带文件偏移，每份报告都带逐区段 SHA-256 —— 人或另一个 agent 可以自己复核，而不是选择相信。

**设计原则**

1. **证据优先于结论**：每次命中的都给出区段名 / 标记串 / 字节模式 / overlay 偏移。
2. **绝不执行**：没有模拟器、没有加载器、不 `CreateProcess`、不联网。
3. **诚实标注未知**：不支持的格式与未解析的间接跳转如实说明。
4. **有界计算**：所有循环都有上限；畸形/截断输入返回"部分事实 + 明确局限"，而不是抛异常。

---

## 功能一览

| 领域 | 内容 |
|---|---|
| **保护识别** | 25 个家族签名（UPX、ASPack、PECompact、MPRESS、Themida/WinLicense、VMProtect、Enigma、Armadillo、.NET Reactor、ConfuserEx、KoiVM、PyInstaller、Electron、NSIS、Inno、Go、Rust…）+ 结构启发式（仅虚拟区段、RWX、入口在末段、校验和不符、IAT 搬离 `.idata`、高熵区段） |
| **OEP 猎人** | 用长度精确的 x86/x86-64 解码器走入口 stub，识别 `push imm32; ret`、跨段相对跳转、`popad` 后转移；给候选打分；输出 ESP 定律与 x64dbg/gdb/WinDbg 断点方案 |
| **导入重建** | 模块/函数现状、ordinal-only 统计、IAT 位置对照、**残留 `IMAGE_IMPORT_DESCRIPTOR` 数组扫描**、重建步骤与 Scylla/x64dbg 命令 |
| **反分析** | PEB（`fs:[0x30]` / `gs:[0x60]`）、NtGlobalFlag、`rdtsc`、`int 2d`、`icebp`、`ud2`、CPUID 虚拟机探测、VMware 后门端口；TLS 回调；IAT hook 目标与建议返回值；**带文件偏移的 NOP 补丁** |
| **托管层** | CLR 头、元数据流（`#~`/`#Strings`/`#US`/`#Blob`/`#GUID`）、表行数、混淆器指纹、混淆强度指标 |
| **dump 修复** | 内存镜像 → 可解析文件：区段重排、`SizeOfRawData`/`PointerToRawData`/`SizeOfImage`/`SizeOfHeaders` 重写、PE 校验和重算，修复后再解析自校验 |
| **脚本生成** | x64dbg / gdb / WinDbg / Scylla / Frida 全套（PEB 修补、API 拦截、RWX 监听、OEP 命中自动 dump） |
| **报告** | Markdown + JSON + 逐区段证据链（E-001 …） |

---

## 三步开始

```bash
git clone https://github.com/lingbol088-spec/local-binary-index.git
cd local-binary-index
npm ci && npm test        # 编译 + 生成合成样本 + 10 项单测
```

### 接成 MCP 服务

**Codex 桌面端 / CLI（`~/.codex/config.toml`）**

```toml
[mcp_servers.local-binary-index]
command = "node"
args = ["/abs/path/to/local-binary-index/bin/lbi-mcp.mjs"]
startup_timeout_sec = 60

[mcp_servers.local-binary-index.env]
LBI_TOKEN = "zxwn"
```

**Claude Desktop / Cursor（`mcpServers` JSON）**

```json
{
  "mcpServers": {
    "local-binary-index": {
      "command": "node",
      "args": ["/abs/path/to/local-binary-index/bin/lbi-mcp.mjs"],
      "env": { "LBI_TOKEN": "zxwn" }
    }
  }
}
```

**新开一个对话**，然后：

```text
你：zxwn
它：（能力表）要分析哪个文件？
你：D:\samples\target.exe 是什么壳，怎么脱
```

### 用 CLI

```bash
npx lbi status
npx lbi zxwn profile  samples/packed.exe
npx lbi zxwn transfer samples/packed.exe
npx lbi zxwn imports  samples/packed.exe
npx lbi zxwn anti     samples/packed.exe
npx lbi zxwn managed  samples/assembly.dll
npx lbi zxwn analyze  samples/packed.exe --out ./out
npx lbi zxwn repair-dump dump.bin --out fixed.exe
```

除 `analyze`（写文件）外都支持 `--json`。

---

## 8 个 MCP 工具

| 工具 | 回答什么问题 | 关键输出 |
|---|---|---|
| `inspect_protection_profile` | 这是什么，破它要做什么 | 判定、家族、置信度、逐条证据、结构异常、处置路线 |
| `inspect_entry_transfer` | 原始代码从哪开始 | 打分的 OEP 候选（含来源指令）、ESP 定律、三套断点命令 |
| `inspect_import_rebuild_plan` | 导入表去哪了 | IAT 现状、ordinal-only、残留描述符、重建步骤 |
| `inspect_anti_analysis` | 会怎么跟调试器对抗 | 命中项 + 文件偏移、可安全 NOP 的补丁、hook 目标、TLS 回调 |
| `inspect_managed_protection` | 是不是 .NET、混淆多重 | CLR 版本、流表、表行数、混淆器标记 |
| `repair_image_dump` | 这个 dump 能不能解析 | 区段重排、头重写、校验和重算、修复后自校验 |
| `emit_recovery_scripts` | 调试器里贴什么 | x64dbg / gdb / WinDbg / Scylla / Frida 文件 |
| `inspect_binary_report` | 全都要 | Markdown + JSON + 证据链 |

字段级 schema：**[docs/TOOLS.md](docs/TOOLS.md)**。

---

## 触发词与上膛机制

| 状态 | 条件 | `tools/list` |
|---|---|---|
| 静默 | 无 `LBI_TOKEN`，或状态文件缺失/过期 | 1 个（`index_status`） |
| 上膛 | `LBI_TOKEN=zxwn`，或状态文件为 `zxwn` 且未过期 | 8 个 |

```bash
lbi zxwn arm --minutes 1440   # 上膛 24 小时（0 = 不过期）
lbi zxwn disarm               # 立即回静默
lbi status                    # 查看状态与到期时间
```

为什么默认静默：分析工作站上通常挂着多个 MCP 服务，让二进制分析面在你明确上膛前保持不可见，误用与审计都更清楚。

---

## 工作流

```text
                  ┌──────────────────────────────────────────────────────┐
   file bytes ──▶ │ peFile  头/区段/导入/导出/TLS/资源/调试/Rich/overlay  │
                  └───────────────┬──────────────────────────────────────┘
                                  │  PeImage（RVA⇄偏移 解析 + 结构异常）
        ┌─────────────────────────┼───────────────────────────┬─────────────────────┐
        ▼                         ▼                           ▼                     ▼
  packer/detect             oep/x86len + hunt            iat/plan            antidebug/scan
  签名 + 结构启发式          stub 走查 → 候选              IAT 现状 +          特征 + IAT hook
  → 家族、置信度            ESP 定律 + 断点               残留描述符          → 补丁、hook 目标
        └────────────┬────────────┴─────────────┬─────────────┴──────────┬──────────┘
                     ▼                          ▼                        ▼
              runtime/scripts            runtime/fixDump          report/markdown
              x64dbg/gdb/windbg          dump → 文件布局           Markdown + JSON + 证据
              scylla/frida               + 校验和重算
```

全部是对 `Uint8Array` 的纯计算；唯一的 I/O 是读目标文件、按需写报告与脚本。

---

## 实测数据

| 目标 | 结果 |
|---|---|
| 合成 UPX 形态 PE32（5,136 B） | `packed`（1.0）· UPX · OEP `0x401000` 得分 100 · 补丁 `int 2d @0x00000A10 → 90 90` · 残留描述符 `@0x00005500` = USER32.dll, GDI32.dll |
| `notepad.exe`（x64 真实系统文件） | `clean` · 50 模块 / 315 导入 · 12 条反分析命中 · 0 结构异常 |
| `mscorlib.dll`（.NET 4） | CLR `v1.1` · metadata `v4.0.30319` · 31 张表 · TypeDef 3,356 / MethodDef 29,257 |
| 24,576 B 内存 dump | 内存→文件重排 · 指针重写 · 校验和重算 · 重解析通过 |

本地复现：`npm run fixtures && npm run demo`。

---

## 兼容性

| 项 | 支持 |
|---|---|
| 输入格式 | PE32 / PE32+（EXE、DLL、SYS）；.NET 程序集 |
| 不支持 | ELF、Mach-O、16 位 NE/LE（明确报错） |
| 宿主系统 | Windows / macOS / Linux（纯 Node） |
| Node | ≥ 20.11 |
| 运行时依赖 | 无 |
| MCP 传输 | stdio |

---

## 安全模型

- **只读**：打开文件，不做可执行映射，不启动目标。
- **不联网**：无遥测、无远端查询、无签名下载。
- **不含样本**：测试样本由 `scripts/make-fixtures.mjs` 本地生成，是合成字节。
- **可复核**：同样的字节得到同样的 JSON，报告带哈希。

---

## 局限

- 静态分析无法还原加密壳的载荷；这类需要运行时 dump（脚本能把你送到那一步，分析本身不行）。
- 单字节特征（如 `F1` icebp）在随机数据里可能巧合命中；已限制命中上限并标注。
- x86-64 的 VEX/EVEX 只按长度近似解码，遇到非法字节立即停止并报告位置。
- IAT 重建是"计划 + 残留描述符发现"，不是 Scylla 的自动替代品。
- .NET 只做结构读取，不反编译 IL（请用专门的 decompiler 处理输出）。

---

## 常见问题

**它会脱壳吗？**
不会。它告诉你**怎么**脱，并生成负责运行时部分（dump、断点、hook）的调试器/Frida 资产。

**为什么默认是静默目录？**
避免共享工作站上悄悄多出一个二进制分析攻击面。用 `zxwn` 上膛，可设置有效期。

**能商用吗？**
MIT 允许。但请先读 [DISCLAIMER.md](DISCLAIMER.md)——合规责任仍在使用方。

**面对未知二进制从哪开始？**
`analyze` → 看 `protection.verdict` 与 `entryTransfer.candidates[0]` → 打开生成的 x64dbg 脚本。

---

## 路线图

- [ ] ELF 支持（壳识别 + `.init_array` 分析）
- [ ] Mach-O 支持
- [ ] Scylla 兼容的 `.scv` IAT 导出
- [ ] 从检测信号导出 YARA 规则
- [ ] 解析核心的 WASM 构建（浏览器端分流）

---

## 参与

Issue / PR 都欢迎，见 [CONTRIBUTING.md](CONTRIBUTING.md)。提 PR 前请跑 `npm test`，新增检测签名必须自带可复现样本。

## 安全

漏洞请按 [SECURITY.md](SECURITY.md) 私下报告，不要在公开 issue 里贴可利用细节。

## 许可

[MIT](LICENSE) © 2026 li lingbo

## 免责声明

本软件按**“现状”**提供，不附带任何担保。仅限用于对你**拥有或已获授权**的二进制做合法分析（安全研究、应急响应、CTF、隔离环境下的样本分析）。不得用于规避你无权处理的软件保护、开发或传播恶意软件，或违反任何适用法律。作者不对误用或损害承担责任。全文：**[DISCLAIMER.md](DISCLAIMER.md)**。
