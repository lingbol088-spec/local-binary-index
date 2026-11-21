---
name: binary-analysis
description: 逆向与脱壳分析任务：加壳识别、脱壳、OEP 定位、IAT 重建、反调试/反虚拟机、.NET 混淆、内存 dump 修复、PE 结构分析。凡涉及 PE 样本、壳、脱壳、dump、IAT、反调试、混淆器，优先调用已注册的 local-binary-index MCP 工具，不要凭经验猜壳或手算偏移。
---

# 二进制分析（统一走 local-binary-index MCP）

## 用哪个 MCP

固定使用 **`local-binary-index`**（Codex 全局 MCP，stdio 传输，与项目无关）。

核实命令：

```powershell
& "$((Get-AppxPackage OpenAI.Codex).InstallLocation)\app\resources\codex.exe" mcp get local-binary-index
```

期望：`enabled: true` / `transport: stdio` / `command` 指向 node / `args` 指向 `...\LocalBinaryIndex\payload\bin\lbi-mcp.mjs`。

先跑 `%LOCALAPPDATA%\LocalBinaryIndex\tools\status.cmd -Json` 判定：

| state | 动作 |
|---|---|
| `ready` | 直接输出能力表，结尾提示「MCP 已就绪；看不到工具就新开一个对话」 |
| `installed-needs-reload` | 不重启 Codex，提示「已安装但当前对话未加载，请新开一个对话」 |
| `not-deployed` | 先说明「检测到未部署，我现在自部署（不重启 Codex）」，运行 `%LOCALAPPDATA%\LocalBinaryIndex\tools\ensure.cmd`，成功后提示「部署完成，请新开一个对话」 |

失败就把 status/ensure 的报错贴给用户；**不要 kill 或重启 Codex**。
仍失败就把 `codex mcp get local-binary-index` 与 `codex mcp list` 的原始输出贴给用户，不要自己造工具名。

## 工具路由（只有这 8 个入口，别猜）

| 用户想要 | 调用工具 | 关键参数 |
|---|---|---|
| 判断有没有加壳 / 什么壳 / 怎么脱 | `inspect_protection_profile` | `path` |
| 找入口 / OEP / 去哪下断 | `inspect_entry_transfer` | `path`、可选 `include_internal_jumps` |
| 导入表被抹 / IAT 重建 | `inspect_import_rebuild_plan` | `path` |
| 反调试 / 反虚拟机 / 怎么过 | `inspect_anti_analysis` | `path` |
| .NET / 混淆器 / 去混淆 | `inspect_managed_protection` | `path` |
| 内存 dump 打不开 | `repair_image_dump` | `path`、可选 `output_path` |
| 要 x64dbg/gdb/Frida 脚本 | `emit_recovery_scripts` | `path`、可选 `out_dir` |
| 要一份完整交付报告 | `inspect_binary_report` | `path`、可选 `out_dir`、`format` |

## 默认流水线（一次任务按需取用）

1. `inspect_protection_profile` → 拿 verdict / 家族 / 处置路线，决定后续走哪条
2. `inspect_entry_transfer` → OEP 候选 + ESP 定律 + 断点命令
3. `inspect_import_rebuild_plan` → IAT 现状 + 残留描述符 + 重建步骤
4. `inspect_anti_analysis` → 反调试项 + 可 NOP 补丁（带文件偏移）+ hook 目标
5. `inspect_managed_protection` → 仅当 CLR 目录存在（.NET）
6. `repair_image_dump` → 有内存镜像时先修再分析
7. `emit_recovery_scripts` → 需要落地脚本时
8. `inspect_binary_report` → 需要交付/存档时（Markdown + JSON + 证据链）

## 硬约束

- 工具**只读不执行样本**；目标是本地路径，不要试图让它联网或跑样本。
- 判定以工具返回的 `verdict`/`score`/`signals` 为准，**不要**用文件名或图标猜壳。
- 引用结论时带上 SHA-256 与 `evidence` 里的 E-xxx id，便于复核。
- 静态结论不等于脱壳成功：涉及加密壳必须补运行时 dump（Frida 脚本由 `emit_recovery_scripts` 产出）。
- 不支持的格式（ELF / Mach-O）直说，不要伪装支持。
- **自部署**：工具缺失时先跑 `ensure.cmd`；不要 kill Codex 进程、不要重启桌面端（会丢用户未保存内容）。

## 输出格式

先结论（壳家族 / 判定 / 关键地址），再证据（工具返回的 signals 与偏移），最后下一步动作（下断点 / dump / 补丁），每段都带可复现的命令或工具调用。

## 自检

```powershell
%LOCALAPPDATA%\LocalBinaryIndex\tools\verify.cmd
```

或直接问服务：

```powershell
node "$env:LOCALAPPDATA\LocalBinaryIndex\payload\bin\lbi.mjs" selfcheck --token zxwn --json
```

期望：`toolCount = 8`、`promptNames` 含 `zxwn`。若 `toolCount = 1`，说明上膛窗口过期，执行：

```powershell
node "$env:LOCALAPPDATA\LocalBinaryIndex\payload\bin\lbi.mjs" zxwn arm --minutes 1440
```
