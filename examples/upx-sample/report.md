# 二进制分析报告

- 样本：`fixtures\packed-sample.exe`
- SHA-256：`f965123c6ff0780a187859ae19e77e6b8f89f5e83f91a0eb46a1beacf10609d1`
- 大小：5136 字节
- 分析时间：2026-11-21T00:44:51.247Z
- 引擎：local-binary-index 1.4.3

## 1. 结论

| 项 | 结论 |
| --- | --- |
| 保护判定 | packed（置信度 1） |
| 主家族 | UPX |
| 架构 / 子系统 | x86 · windows-cui |
| 入口 | 0x0000000000404000（RVA 0x00004000） |
| 导入 | 1 模块 / 3 函数 |
| 反分析得分 | 54 |
| 托管代码 | 否 |

### 处置路线
- 【UPX】开源压缩壳；保留原始导入表与原始入口线索，可直接 -d 脱壳。
- 首选：`upx -d <input> -o <output>`（版本需 >= 壳版本，否则 `-d --force` 试）
- 失败时走通用 OEP 路线：stub 尾部 push imm32;retn 即原始入口
- 脱壳后校验导入表：UPX 保留 ILT，可直接重建

## 2. 结构

| # | 区段 | RVA | VirtualSize | RawSize | 熵 | 权限 | 异常 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | .text | 0x00001000 | 4096 | 1536 | 0.0548 | X-RC |  |
| 1 | UPX0 | 0x00002000 | 8192 | 0 | 0 | -WR- |  |
| 2 | UPX1 | 0x00004000 | 4096 | 1024 | 7.8213 | XWRC |  |
| 3 | .idata | 0x00005000 | 4096 | 1536 | 0.671 | -WR- |  |

结构异常：
- [high] virtual-only-section: 区段 UPX0 无文件数据但有 VirtualSize 8192（典型解压目标 / UPX0 形态）
- [high] rwx-section: 区段 UPX1 同时可写可执行（RWX）

overlay：偏移 0x00001400，16 字节，熵 2.2169，标记 UPX!

## 3. 保护指纹

| 家族 | 类别 | 难度 | 置信度 | 命中证据 |
| --- | --- | --- | --- | --- |
| UPX | packer | trivial | 1 | section-name:区段名精确命中 UPX0；section-name:区段名精确命中 UPX1；ascii-marker:文件内出现标记 "UPX!"（2 处）；byte-pattern:upx2/3-entry(pushad;mov esi,imm;lea edi,[esi+imm]) @ 0x00000A00 → 60 BE 00 10 40 00 8D BE；overlay-marker:overlay 内出现标记 "UPX!" |

通用结构信号：
- (12) 入口所在区段熵 7.8213（stub 自身被压缩/加密）
- (20) 1 个区段只有虚拟大小（解压目标）: UPX0
- (14) RWX 区段: UPX1
- (16) 导入函数总数仅 3（壳把真实导入藏在运行时）

## 4. 入口转移（OEP）

stub：解码 436 条指令，停止原因 section-end，pushad 0x00000A00，控制转移 8 次

| 得分 | 来源 | 候选 RVA | 候选 VA | 区段 | 证据 |
| --- | --- | --- | --- | --- | --- |
| 100 | push-ret | 0x00001000 | 0x0000000000401000 | .text | 尾部跳转惯用法 push 0x00401000 ; ret（ret @ 0x00000A1E）；立即数按 VA 解释（>= ImageBase） |

## 5. 导入表重建

当前：1 模块，IAT @ 0x00005200（.idata），ordinal-only 0

残留原始描述符候选：
- 得分 66 @ 0x00005500：USER32.dll, GDI32.dll
- 得分 54 @ 0x00005514：GDI32.dll

重建步骤：
- 1) 在 OEP 断点命中、且目标区段已解压（内存里可执行区段熵下降）后再 dump，过早 dump 只能拿到壳的 stub
- 2) dump 落盘后先修区段表（本工具的 fix-dump 子命令），否则文件无法被 RVA→偏移解析
- 3) IAT 重建优先级：① 二进制残留的原始描述符（见 descriptorCandidates）→ ② Scylla 自动扫描 → ③ 手工记录调用点
- 4) 校验：重建后所有导入函数名可解析、且 IAT 槽位按调用约定可读；再跑一次本工具确认 imports 非空且无 ordinal-only 泛滥
- 5) 若仍有 ordinal-only 导入，按序数在对应系统 DLL 的导出表反查名字补全
- 6) 已发现 2 组疑似原始导入描述符，最高分位于 0x00005500（USER32.dll,GDI32.dll）

## 6. 反分析

| 类别 | 级别 | 标题 | 位置 | 原始字节 | 落地建议 |
| --- | --- | --- | --- | --- | --- |
| anti-debug | high | INT 2D 反调试（内核调试器异常） | 0x0000000000404010 | CD 2D | 90 90 |
| anti-debug | medium | ICEBP / INT1 指令 | 0x0000000000404012 | F1 | 90 |
| anti-debug | medium | ICEBP / INT1 指令 | 0x00000000004040F8 | F1 | 90 |
| anti-debug | medium | ICEBP / INT1 指令 | 0x000000000040412A | F1 | 90 |
| anti-debug | medium | ICEBP / INT1 指令 | 0x000000000040437B | F1 | 90 |
| tls | high | TLS 回调（入口点之前执行） | 0x0000000000401000 | - | - |

可直接落地的补丁：
- 0x00000A10 → `90 90`（int2d: INT 2D 反调试（内核调试器异常）（CD 2D））
- 0x00000A12 → `90`（icebp: ICEBP / INT1 指令（F1））
- 0x00000AF8 → `90`（icebp: ICEBP / INT1 指令（F1））
- 0x00000B2A → `90`（icebp: ICEBP / INT1 指令（F1））
- 0x00000D7B → `90`（icebp: ICEBP / INT1 指令（F1））

运行期 hook 目标：
- KERNEL32.dll!IsDebuggerPresent @ 0x0000000000405200（anti-debug，返回 0（FALSE））
- KERNEL32.dll!VirtualProtect @ 0x0000000000405204（process-guard，记录 RWX 转换（也是解压完成信号））
- KERNEL32.dll!GetTickCount @ 0x0000000000405208（timing，返回可控常量或慢速递增）

## 7. 证据链

| ID | 类型 | 说明 | 摘要 |
| --- | --- | --- | --- |
| E-001 | sample | 样本 fixtures\packed-sample.exe（5136 字节） | f965123c6ff0780a |
| E-002 | pe-structure | i386 / windows-cui / 4 区段 / 入口 0x0000000000404000 | f965123c6ff0780a |
| E-003 | protection | packed · UPX · 置信度 1 | f965123c6ff0780a |
| E-004 | section | .text @ RVA 0x00001000 raw 1536 entropy 0.0548 | 55854af21149d915 |
| E-005 | section | UPX0 @ RVA 0x00002000 raw 0 entropy 0 | e3b0c44298fc1c14 |
| E-006 | section | UPX1 @ RVA 0x00004000 raw 1024 entropy 7.8213 | ec6fbc024dc562e7 |
| E-007 | section | .idata @ RVA 0x00005000 raw 1536 entropy 0.671 | 87a954707cbc3098 |


## 8. 局限

- 静态 stub 走查无法解析间接跳转（jmp reg / jmp [mem]）的真实目标，只给运行时断点
- 加壳器常插入垃圾字节或花指令，遇到非法指令立即停止（看 stoppedReason）
- x86-64 的 VEX/EVEX 只按长度近似解码，个别指令可能错位
- 候选是「最值得下断的位置」，不是脱壳成功的证明——必须运行时 dump 验证
- 静态扫描只能发现「还在文件里」的原始描述符；被壳搬走/加密的原表必须在内存镜像里找
- IAT 槽位的真实函数名需运行时解析（LoadLibrary/GetProcAddress 的结果才是权威）
- 本模块不写文件、不 patch 输入；落地由 fix-dump 与外部工具完成
- 字节特征按模式匹配，代码段里可能有巧合命中的常量（需人工确认上下文）
- PEB/NtGlobalFlag 类检测不能靠 NOP 解决，必须运行时修补
- 未覆盖：硬件断点检测（DR 寄存器）、时间戳签名校验、内核回调
- 覆盖率为「已扫描可执行区段」，非可执行区段里的数据驱动检测不在其中
- 静态结论不执行样本；加密壳的真实镜像只能由运行时 dump 提供

## 9. 复现

```
node bin/lbi.mjs zxwn analyze "fixtures\packed-sample.exe" --out ./out
```
