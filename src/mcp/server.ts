#!/usr/bin/env node
/**
 * MCP stdio 服务。默认对外只暴露 index_status（无害状态查询）；
 * 只有持触发词时才挂出完整工具面。
 */
import { createInterface } from "node:readline";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import {
  analyzeFile,
  patchFile,
  repairDumpFile,
  writeScripts,
  type BinaryAnalysis,
} from "../index.js";
import { renderMarkdown } from "../report/markdown.js";
import { ACTIVATION_TOKEN, PRODUCT_ID, PRODUCT_VERSION, isActivated } from "../activation.js";
import { toHex } from "../util/bytes.js";

interface JsonRpcRequest {
  readonly jsonrpc?: string;
  readonly id?: number | string | null;
  readonly method?: string;
  readonly params?: Record<string, unknown>;
}

interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

const TOOL_DEFINITIONS: readonly ToolDefinition[] = [
  {
    name: "inspect_protection_profile",
    description:
      "在本地离线读取一个 PE32/PE32+ 镜像，识别压缩壳/保护器/虚拟化/混淆器/打包器家族，给出证据、置信度与处置路线。返回判定、命中家族与每条命中的具体信号（区段名、标记字符串、字节模式偏移、overlay 标记），以及结构级通用信号（虚拟独占区段、RWX 区段、入口落在末区段、校验和不符、IAT 被搬移、高熵区段）。不执行样本，不访问网络。",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "本地镜像路径" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_entry_transfer",
    description:
      "从入口点顺序解码 x86/x86-64 stub，定位原始入口点(OEP)候选：尾部 push imm32;ret 惯用法、跨越入口区段的相对跳转、popad 后的转移；并输出 ESP 定律、寄存器/内存间接转移与可直接执行的断点命令。返回 stub 解码统计、候选列表（得分/证据/来源指令）、断点列表。静态结果需运行时验证。",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "本地镜像路径" },
        include_internal_jumps: {
          type: "boolean",
          description: "是否把入口区段内部的相对跳转也作为候选返回（默认 false）",
        },
        max_instructions: { type: "number", description: "stub 解码上限（默认 20000）" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_import_rebuild_plan",
    description:
      "测绘导入表现状并给出重建方案：模块/函数计数、IAT 目录与所在区段、ordinal-only 数量、IAT 是否被搬离导入区段；扫描文件中残留的原始 IMAGE_IMPORT_DESCRIPTOR 数组（含计分与模块名）；输出重建步骤与工具命令（Scylla/x64dbg）。只读，不修改样本。",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "本地镜像路径" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_anti_analysis",
    description:
      "扫描反调试/反虚拟机/时序/完整性校验特征：PEB.BeingDebugged 读取、NtGlobalFlag、RDTSC、INT 2D、ICEBP、UD2、CPUID 虚拟机探测、VMware 后门端口；解析 IAT 中的反分析 API 并给出 hook 目标与建议返回值；列出 TLS 回调与可安全 NOP 的补丁字节（带文件偏移）。返回发现项、补丁清单与 hook 表。",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "本地镜像路径" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_managed_protection",
    description:
      "对 .NET 程序集做离线结构分析：CLR 头、元数据版本、流表（#~/#Strings/#US/#Blob/#GUID）、表行数（TypeDef/MethodDef/Field/MemberRef/AssemblyRef）、混淆器指纹与混淆强度指标，并给出处置步骤。不加载程序集、不执行 IL。",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", description: "本地镜像路径" } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "repair_image_dump",
    description:
      "把内存 dump 还原为可解析的文件镜像：按 VirtualAddress 重排各区段、重写 SizeOfRawData/PointerToRawData/SizeOfImage/SizeOfHeaders、重算 PE 校验和，并在修复后重新解析做自校验（入口落点、镜像大小）。返回每条区段的重排结果、字段变更与警告；可选写出修复后的文件。",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "待修复的镜像路径" },
        output_path: { type: "string", description: "修复结果写出路径（可选）" },
        force_memory_layout: { type: "boolean", description: "强制按内存布局重排" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "emit_recovery_scripts",
    description:
      "为指定样本生成可执行脚本集合：x64dbg 断点脚本、gdb 命令、WinDbg 命令、Frida 运行期脚本（PEB 修补、反调试 API 覆盖、RWX 转换监听、OEP 命中 dump、模块镜像落盘）与 IAT 重建命令；写出到目录并返回文件路径。",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "本地镜像路径" },
        out_dir: { type: "string", description: "脚本输出目录（默认 ./scripts-out）" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_binary_report",
    description:
      "一次性完整分析并生成 Markdown 报告 + JSON：结构、保护指纹、入口转移、导入重建、反分析、托管层、证据链（带 SHA-256）与局限。可选写出报告与脚本到目录。",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "本地镜像路径" },
        out_dir: { type: "string", description: "报告与脚本输出目录（可选）" },
        format: { type: "string", enum: ["markdown", "json"], description: "返回格式（默认 markdown）" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
];

/** 触发词 zxwn 的应答内容：能力表（AGENTS.md 与本 prompt 共用同一份文案）。 */
export const CAPABILITY_MENU = [
  "我可以帮你做这些（本地二进制分析，全部离线、只读、不执行样本）：",
  "",
  "| # | 能力 | 工具 | 说明 |",
  "|---|---|---|---|",
  "| 1 | 保护指纹 | `inspect_protection_profile` | 识别压缩壳/保护器/虚拟化/混淆器/打包器（25 族签名 + 结构启发式），给证据与处置路线 |",
  "| 2 | 入口转移 | `inspect_entry_transfer` | 从 stub 找 OEP 候选（push imm32;ret / 跨段 jmp / popad 后转移）+ ESP 定律 + 断点命令 |",
  "| 3 | 导入重建 | `inspect_import_rebuild_plan` | IAT 现状、ordinal-only 统计、残留原始描述符扫描、重建步骤 |",
  "| 4 | 反分析 | `inspect_anti_analysis` | 反调试/反虚拟机/时序/完整性特征 + IAT hook 目标 + 可 NOP 补丁（带文件偏移） |",
  "| 5 | 托管层 | `inspect_managed_protection` | .NET CLR 头、元数据流、表行数、混淆器指纹 |",
  "| 6 | dump 修复 | `repair_image_dump` | 内存镜像 → 可解析文件（重排区段、重写指针、重算校验和） |",
  "| 7 | 脚本生成 | `emit_recovery_scripts` | x64dbg / gdb / WinDbg / Frida / Scylla 脚本落盘 |",
  "| 8 | 全量报告 | `inspect_binary_report` | 一次跑完 → Markdown + JSON + 证据链（每段 SHA-256） |",
  "",
  "支持 PE32/PE32+（EXE/DLL/SYS），含 .NET；不支持 ELF/Mach-O。",
  "用法：直接给本地文件路径，例如 `D:\\samples\\target.exe`；也可以说要哪一项（如“看壳”“找 OEP”“修 IAT”）。",
  "要分析哪个文件？",
].join("\n");

const SERVER_INSTRUCTIONS = [
  "本地二进制分析服务。触发词 zxwn：当用户消息仅为 zxwn 时，直接输出能力表（不要反问）。",
  "工具：inspect_protection_profile / inspect_entry_transfer / inspect_import_rebuild_plan / inspect_anti_analysis / inspect_managed_protection / repair_image_dump / emit_recovery_scripts / inspect_binary_report。",
  "未持触发词时只提供 index_status。",
].join(" ");

const INACTIVE_TOOLS: readonly ToolDefinition[] = [
  {
    name: "index_status",
    description: "本地索引服务状态：版本与就绪情况。",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

const jsonResult = (value: unknown): unknown => ({
  content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
});

const errorResult = (message: string): unknown => ({
  content: [{ type: "text", text: message }],
  isError: true,
});

const summarize = (analysis: BinaryAnalysis) => ({
  source: analysis.source,
  product: analysis.product,
  verdict: analysis.protection.verdict,
  confidence: analysis.protection.confidence,
  primary_family: analysis.protection.primaryFamily,
  families: analysis.protection.families.slice(0, 6).map((family) => ({
    family: family.family,
    category: family.category,
    difficulty: family.difficulty,
    confidence: family.confidence,
    signals: family.signals,
  })),
  generic_signals: analysis.protection.genericSignals,
  entry: analysis.image.entryPoint,
  sections: analysis.image.sections,
  anomalies: analysis.image.anomalies,
  evidence: analysis.evidence,
  limitations: analysis.limitations,
});

const requireString = (args: Record<string, unknown> | undefined, key: string): string => {
  const value = args?.[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`参数 ${key} 必须是字符串`);
  }
  return value;
};

const callTool = (name: string, args: Record<string, unknown> | undefined): unknown => {
  switch (name) {
    case "index_status":
      return jsonResult({ product: PRODUCT_ID, version: PRODUCT_VERSION, ready: true });
    case "inspect_protection_profile": {
      const analysis = analyzeFile(requireString(args, "path"));
      return jsonResult(summarize(analysis));
    }
    case "inspect_entry_transfer": {
      const includeInternal = args?.include_internal_jumps === true;
      const maxInstructions = typeof args?.max_instructions === "number" ? args.max_instructions : undefined;
      const analysis = analyzeFile(requireString(args, "path"), {
        includeInternalJumps: includeInternal,
        ...(maxInstructions === undefined ? {} : { maxInstructions }),
      });
      return jsonResult(analysis.entryTransfer);
    }
    case "inspect_import_rebuild_plan": {
      const analysis = analyzeFile(requireString(args, "path"));
      return jsonResult(analysis.imports);
    }
    case "inspect_anti_analysis": {
      const analysis = analyzeFile(requireString(args, "path"));
      return jsonResult({ ...analysis.antiAnalysis, patch_list: analysis.patchList });
    }
    case "inspect_managed_protection": {
      const analysis = analyzeFile(requireString(args, "path"));
      return jsonResult(analysis.managed);
    }
    case "repair_image_dump": {
      const path = requireString(args, "path");
      const outputPath = typeof args?.output_path === "string" ? resolve(args.output_path) : null;
      const result = repairDumpFile(path, outputPath);
      return jsonResult({
        ok: result.ok,
        memory_image: result.memoryImage,
        original_size: result.originalSize,
        repaired_size: result.repairedSize,
        sha256_before: result.sha256Before,
        sha256_after: result.sha256After,
        sections: result.sections,
        patched_fields: result.patchedFields,
        warnings: result.warnings,
        output_path: result.outputPath,
      });
    }
    case "emit_recovery_scripts": {
      const path = requireString(args, "path");
      const outDirectory = resolve(typeof args?.out_dir === "string" ? args.out_dir : "./scripts-out");
      const analysis = analyzeFile(path);
      mkdirSync(outDirectory, { recursive: true });
      const written = writeScripts(analysis, outDirectory);
      writeFileSync(
        resolve(outDirectory, "report.md"),
        "\uFEFF" + renderMarkdown(analysis) + "\n",
        "utf8",
      );
      return jsonResult({ written, report: resolve(outDirectory, "report.md") });
    }
    case "inspect_binary_report": {
      const path = requireString(args, "path");
      const analysis = analyzeFile(path);
      const outDirectory = typeof args?.out_dir === "string" ? resolve(args.out_dir) : null;
      if (outDirectory) {
        mkdirSync(outDirectory, { recursive: true });
        writeFileSync(resolve(outDirectory, "analysis.json"), `${JSON.stringify(analysis, null, 2)}\n`, "utf8");
        writeFileSync(resolve(outDirectory, "report.md"), "\uFEFF" + renderMarkdown(analysis) + "\n", "utf8");
        writeScripts(analysis, resolve(outDirectory, "scripts"));
      }
      if (args?.format === "json") return jsonResult(analysis);
      return { content: [{ type: "text", text: renderMarkdown(analysis) }] };
    }
    case "patch_bytes": {
      const path = requireString(args, "path");
      const patches = Array.isArray(args?.patches)
        ? (args.patches as { fileOffset: number; bytes: string; reason: string }[])
        : [];
      const outputPath = typeof args?.output_path === "string" ? resolve(args.output_path) : null;
      const result = patchFile(path, patches, outputPath);
      return jsonResult({
        applied: result.applied,
        rejected: result.rejected,
        sha256_before: result.sha256Before,
        sha256_after: result.sha256After,
        output_path: result.outputPath,
      });
    }
    default:
      throw new Error(`未知工具: ${name}`);
  }
};

export const startServer = (): void => {
  const activated = isActivated();
  const trace = (label: string, detail: unknown): void => {
    const text = detail instanceof Error ? detail.stack ?? detail.message : String(detail);
    process.stderr.write(`[${label}] ${text}\n`);
  };
  process.on("uncaughtException", (error) => trace("uncaught", error));
  process.on("unhandledRejection", (reason) => trace("unhandled", reason));
  const tools = activated ? TOOL_DEFINITIONS : INACTIVE_TOOLS;
  const respond = (payload: unknown): void => {
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  };

  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;
    let request: JsonRpcRequest;
    try {
      request = JSON.parse(trimmed) as JsonRpcRequest;
    } catch {
      respond({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    const id = request.id ?? null;
    const method = request.method ?? "";

    try {
      switch (method) {
        case "initialize": {
          const requested = request.params?.["protocolVersion"];
          respond({
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion: typeof requested === "string" ? requested : "2024-11-05",
              capabilities: activated ? { tools: { listChanged: false }, prompts: {} } : { tools: { listChanged: false } },
              serverInfo: { name: PRODUCT_ID, version: PRODUCT_VERSION },
              instructions: SERVER_INSTRUCTIONS,
            },
          });
          return;
        }
        case "notifications/initialized":
        case "notifications/cancelled":
          return;
        case "ping":
          respond({ jsonrpc: "2.0", id, result: {} });
          return;
        case "tools/list":
          respond({ jsonrpc: "2.0", id, result: { tools } });
          return;
        case "tools/call": {
          const name = typeof request.params?.["name"] === "string" ? (request.params["name"] as string) : "";
          const args =
            request.params?.["arguments"] !== null && typeof request.params?.["arguments"] === "object"
              ? (request.params?.["arguments"] as Record<string, unknown>)
              : undefined;
          const allowed = tools.some((tool) => tool.name === name) || (activated && name === "patch_bytes");
          if (!allowed) {
            respond({ jsonrpc: "2.0", id, result: errorResult(`未知工具: ${name}`) });
            return;
          }
          try {
            respond({ jsonrpc: "2.0", id, result: callTool(name, args) });
          } catch (error) {
            respond({
              jsonrpc: "2.0",
              id,
              result: errorResult(error instanceof Error ? `${error.name}: ${error.message}` : String(error)),
            });
          }
          return;
        }
        case "resources/list":
          respond({ jsonrpc: "2.0", id, result: { resources: [] } });
          return;
        case "prompts/list":
          respond({
            jsonrpc: "2.0",
            id,
            result: {
              prompts: activated
                ? [
                    {
                      name: ACTIVATION_TOKEN,
                      title: "本地二进制分析能力表",
                      description: "输出 8 项能力表与路由规则，用于「zxwn」触发词回应。",
                      arguments: [],
                    },
                  ]
                : [],
            },
          });
          return;
        case "prompts/get": {
          const promptName = typeof request.params?.["name"] === "string" ? (request.params["name"] as string) : "";
          if (!activated || promptName !== ACTIVATION_TOKEN) {
            respond({ jsonrpc: "2.0", id, result: { description: "unknown prompt", messages: [] } });
            return;
          }
          respond({
            jsonrpc: "2.0",
            id,
            result: {
              description: "本地二进制分析能力表",
              messages: [{ role: "user", content: { type: "text", text: CAPABILITY_MENU } }],
            },
          });
          return;
        }
        default:
          respond({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
      }
    } catch (error) {
      respond({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
      });
    }
  });

  process.on("SIGINT", () => process.exit(0));
  process.on("SIGTERM", () => process.exit(0));
  process.stderr.write(
    `${PRODUCT_ID} ${PRODUCT_VERSION} ready (${activated ? "full" : "limited"} catalog, ${tools.length} tools)\n`,
  );
};

export const describeToolCatalog = (): typeof TOOL_DEFINITIONS => TOOL_DEFINITIONS;
export const describeInactiveCatalog = (): typeof INACTIVE_TOOLS => INACTIVE_TOOLS;
export const describeActivationToken = (): string => ACTIVATION_TOKEN;
void toHex;
