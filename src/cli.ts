#!/usr/bin/env node
/**
 * 命令行入口。除 status/version/--help 外，所有操作都要求触发词。
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeFile,
  patchFile,
  repairDumpFile,
  writeScripts,
  type AnalyzeOptions,
} from "./index.js";
import { renderMarkdown } from "./report/markdown.js";
import { runSelfCheck } from "./selfcheck.js";
import {
  ACTIVATION_TOKEN,
  DEFAULT_ARM_MINUTES,
  PRODUCT_ID,
  PRODUCT_VERSION,
  arm,
  disarm,
  isActivated,
  readState,
  stateFilePath,
} from "./activation.js";
import { toHex } from "./util/bytes.js";

const USAGE = `local-binary-index ${PRODUCT_VERSION}

用法:
  <入口> status                     查看服务状态（无需触发词）
  <入口> version                    版本信息
  <入口> selfcheck [--token zxwn|--no-token] [--state-dir DIR] [--entry PATH] [--sample FILE] [--json]
                                    自检：真实握手一次，报告工具数（无需触发词）
  <入口> ${ACTIVATION_TOKEN} arm [--minutes N] 上膛（触发词生效 N 分钟，默认 1440）
  <入口> ${ACTIVATION_TOKEN} disarm         撤膛（立即回到静默目录）
  <入口> ${ACTIVATION_TOKEN} analyze <file> [--json] [--out DIR]
  <入口> ${ACTIVATION_TOKEN} profile <file> [--json]
  <入口> ${ACTIVATION_TOKEN} transfer <file> [--json] [--internal]
  <入口> ${ACTIVATION_TOKEN} imports <file> [--json]
  <入口> ${ACTIVATION_TOKEN} anti <file> [--json]
  <入口> ${ACTIVATION_TOKEN} managed <file> [--json]
  <入口> ${ACTIVATION_TOKEN} scripts <file> --out DIR
  <入口> ${ACTIVATION_TOKEN} repair-dump <file> [--out FILE]
  <入口> ${ACTIVATION_TOKEN} patch <file> --patches JSON [--out FILE]

触发词也可通过环境变量 LBI_TOKEN 提供。
`;

interface ParsedArgs {
  readonly command: string;
  readonly positional: readonly string[];
  readonly flags: ReadonlyMap<string, string | true>;
}

const parseArgs = (argv: readonly string[]): ParsedArgs => {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === undefined) continue;
    if (token.startsWith("--")) {
      const name = token.slice(2);
      const next = argv[index + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags.set(name, next);
        index += 1;
      } else {
        flags.set(name, true);
      }
      continue;
    }
    positional.push(token);
  }
  const command = positional.shift() ?? "";
  return { command, positional, flags };
};

const printJson = (value: unknown): void => {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const requireToken = (flags: ReadonlyMap<string, string | true>): boolean => {
  if (isActivated()) return true;
  if (flags.get("token") === ACTIVATION_TOKEN) return true;
  process.stderr.write(
    "未激活：需要触发词。用法 " + ACTIVATION_TOKEN + " <command> ... 或设置 LBI_TOKEN=" + ACTIVATION_TOKEN + "\n",
  );
  return false;
};

export const main = async (argv: readonly string[]): Promise<number> => {
  const parsed = parseArgs(argv);
  const { command, positional, flags } = parsed;

  if (command === "" || flags.get("help") === true || command === "help") {
    process.stdout.write(USAGE);
    return 0;
  }
  if (command === "version") {
    process.stdout.write(`${PRODUCT_ID} ${PRODUCT_VERSION}\n`);
    return 0;
  }
  if (command === "selfcheck") {
    const here = dirname(fileURLToPath(import.meta.url));
    const defaultEntry = resolve(here, "..", "..", "bin", "lbi-mcp.mjs");
    const entryRaw = flags.get("entry");
    const tokenRaw = flags.get("token");
    const noToken = flags.get("no-token") === true;
    const stateRaw = flags.get("state-dir");
    const sampleRaw = flags.get("sample");
    const result = await runSelfCheck({
      entry: typeof entryRaw === "string" ? resolve(entryRaw) : defaultEntry,
      token: noToken ? "" : typeof tokenRaw === "string" ? tokenRaw : "zxwn",
      stateDirectory: typeof stateRaw === "string" ? resolve(stateRaw) : null,
      sample: typeof sampleRaw === "string" ? resolve(sampleRaw) : null,
    });
    if (flags.get("json") === true) {
      printJson(result);
    } else {
      process.stdout.write(`tools=${result.toolCount}\n`);
      process.stdout.write(`server=${result.serverName ?? "?"} ${result.serverVersion ?? ""}\n`);
      for (const name of result.toolNames) process.stdout.write(`  - ${name}\n`);
      if (result.sampleVerdict) process.stdout.write(`sample=${result.sampleVerdict}/${result.sampleFamily ?? "?"}\n`);
      if (result.error) process.stdout.write(`error=${result.error}\n`);
    }
    return result.ok ? 0 : 1;
  }  if (command === "status") {
    const activated = isActivated();
    const state = readState();
    printJson({
      product: PRODUCT_ID,
      version: PRODUCT_VERSION,
      activated,
      expires_at: state?.expires_at ?? null,
      state_file: existsSync(stateFilePath()) ? stateFilePath() : null,
      node: process.version,
      platform: process.platform,
    });
    return 0;
  }

  // 触发词位置：第一个位置参数是 zxwn 时剥掉，并视为已授权
  let effective = command;
  const args = [...positional];
  const positionalToken = effective === ACTIVATION_TOKEN;
  if (positionalToken) effective = args.shift() ?? "";
  if (!positionalToken && !requireToken(flags)) return 2;
  if (effective === "") {
    process.stderr.write(USAGE);
    return 2;
  }

  const target = args[0];
  if (target === undefined && effective !== "status") {
    process.stderr.write("缺少目标文件路径\n");
    return 2;
  }
  if (target !== undefined && !existsSync(target)) {
    process.stderr.write(`目标不存在: ${target}\n`);
    return 1;
  }

  try {
    switch (effective) {
      case "arm": {
        const minutesRaw = flags.get("minutes");
        const minutes = typeof minutesRaw === "string" ? Number(minutesRaw) : DEFAULT_ARM_MINUTES;
        if (!Number.isFinite(minutes) || minutes < 0) {
          process.stderr.write("--minutes 必须是非负数字（0 = 不过期）\n");
          return 2;
        }
        const path = arm(minutes);
        printJson({ armed: true, token: ACTIVATION_TOKEN, minutes, state_file: path, expires_at: readState()?.expires_at ?? "" });
        return 0;
      }
      case "disarm": {
        const removed = disarm();
        printJson({ armed: false, removed, activated: isActivated() });
        return 0;
      }
      case "analyze": {
        const analysis = analyzeFile(target ?? "", {
          includeInternalJumps: flags.get("internal") === true,
        } satisfies AnalyzeOptions);
        const outFlag = flags.get("out");
        if (typeof outFlag === "string") {
          const outDirectory = resolve(outFlag);
          mkdirSync(outDirectory, { recursive: true });
          writeFileSync(join(outDirectory, "analysis.json"), `${JSON.stringify(analysis, null, 2)}\n`, "utf8");
          writeFileSync(join(outDirectory, "report.md"), "\uFEFF" + renderMarkdown(analysis) + "\n", "utf8");
          const scripts = writeScripts(analysis, join(outDirectory, "scripts"));
          process.stderr.write(`已写出: ${join(outDirectory, "report.md")}\n`);
          for (const file of scripts) process.stderr.write(`已写出: ${file}\n`);
        }
        if (flags.get("json") === true) {
          printJson(analysis);
        } else {
          process.stdout.write(`${renderMarkdown(analysis)}\n`);
        }
        return 0;
      }
      case "profile": {
        const analysis = analyzeFile(target ?? "");
        if (flags.get("json") === true) printJson(analysis.protection);
        else {
          process.stdout.write(`判定: ${analysis.protection.verdict} (${analysis.protection.confidence})\n`);
          process.stdout.write(`主家族: ${analysis.protection.primaryFamily ?? "无"}\n`);
          for (const family of analysis.protection.families.slice(0, 5)) {
            process.stdout.write(`- ${family.family} [${family.category}] ${family.confidence}\n`);
            for (const signal of family.signals.slice(0, 4)) {
              process.stdout.write(`    ${signal.kind}: ${signal.detail}\n`);
            }
          }
          for (const signal of analysis.protection.genericSignals) {
            process.stdout.write(`* ${signal.detail} (+${signal.weight})\n`);
          }
        }
        return 0;
      }
      case "transfer": {
        const analysis = analyzeFile(target ?? "", { includeInternalJumps: flags.get("internal") === true });
        if (flags.get("json") === true) printJson(analysis.entryTransfer);
        else {
          const { entry, stub, candidates, espLaw } = analysis.entryTransfer;
          process.stdout.write(`入口: ${toHex(entry.va, 16)} (${entry.sectionName ?? "?"})\n`);
          process.stdout.write(`stub: ${stub.decodedInstructions} 条指令，停止于 ${stub.stoppedReason}\n`);
          if (candidates.length === 0) process.stdout.write("无静态 OEP 候选\n");
          for (const candidate of candidates.slice(0, 8)) {
            process.stdout.write(
              `- ${candidate.score.toString().padStart(3)} ${candidate.origin.padEnd(11)} ${toHex(candidate.va, 16)} (${candidate.sectionName ?? "?"})\n`,
            );
          }
          process.stdout.write(`ESP 定律: ${espLaw.applicable ? "适用" : "不适用"} — ${espLaw.reason}\n`);
          for (const line of espLaw.commands) process.stdout.write(`  ${line}\n`);
        }
        return 0;
      }
      case "imports": {
        const analysis = analyzeFile(target ?? "");
        if (flags.get("json") === true) printJson(analysis.imports);
        else {
          const current = analysis.imports.current;
          process.stdout.write(
            `导入: ${current.moduleCount} 模块 / ${current.functionCount} 函数 / ordinal-only ${current.ordinalOnlyCount}\n`,
          );
          process.stdout.write(
            `IAT: ${current.iatRva === null ? "无" : toHex(current.iatRva)} (${current.iatSection ?? "?"})\n`,
          );
          for (const candidate of analysis.imports.descriptorCandidates.slice(0, 5)) {
            process.stdout.write(`残留描述符 ${candidate.score} @ ${toHex(candidate.arrayRva)}: ${candidate.moduleNames.join(", ")}\n`);
          }
          for (const module of analysis.imports.blueprint.slice(0, 12)) {
            process.stdout.write(`- ${module.dll}: ${module.functionCount} 个函数\n`);
          }
        }
        return 0;
      }
      case "anti": {
        const analysis = analyzeFile(target ?? "");
        if (flags.get("json") === true) printJson(analysis.antiAnalysis);
        else {
          process.stdout.write(`反分析得分: ${analysis.antiAnalysis.score}\n`);
          for (const finding of analysis.antiAnalysis.findings.slice(0, 20)) {
            process.stdout.write(
              `[${finding.severity}] ${finding.category} ${finding.title} ${finding.va === null ? "" : toHex(finding.va, 16)}\n`,
            );
          }
          for (const patch of analysis.patchList) {
            process.stdout.write(`PATCH ${toHex(patch.fileOffset)} -> ${patch.bytes} (${patch.reason})\n`);
          }
          for (const hook of analysis.antiAnalysis.hookTargets.slice(0, 15)) {
            process.stdout.write(`HOOK ${hook.dll}!${hook.api} @ ${toHex(hook.iatVa, 16)}: ${hook.suggestedBypass}\n`);
          }
        }
        return 0;
      }
      case "managed": {
        const analysis = analyzeFile(target ?? "");
        if (flags.get("json") === true) printJson(analysis.managed);
        else {
          if (!analysis.managed.isManaged) {
            process.stdout.write("不是 .NET 程序集\n");
          } else {
            process.stdout.write(`CLR 运行时: ${analysis.managed.runtimeVersion ?? "?"}\n`);
            process.stdout.write(`表行数: ${JSON.stringify(analysis.managed.tableRowCounts)}\n`);
            for (const marker of analysis.managed.obfuscatorMarkers) {
              process.stdout.write(`混淆器: ${marker.family} (${marker.marker})\n`);
            }
            for (const indicator of analysis.managed.indicators) process.stdout.write(`- ${indicator}\n`);
          }
        }
        return 0;
      }
      case "scripts": {
        const analysis = analyzeFile(target ?? "");
        const outFlag = flags.get("out");
        const outDirectory = resolve(typeof outFlag === "string" ? outFlag : "./out");
        const files = writeScripts(analysis, outDirectory);
        printJson({ written: files });
        return 0;
      }
      case "repair-dump": {
        const outFlag = flags.get("out");
        const outputPath = typeof outFlag === "string" ? resolve(outFlag) : null;
        const result = repairDumpFile(target ?? "", outputPath);
        printJson({
          ok: result.ok,
          memoryImage: result.memoryImage,
          originalSize: result.originalSize,
          repairedSize: result.repairedSize,
          sha256_before: result.sha256Before,
          sha256_after: result.sha256After,
          patched_fields: result.patchedFields,
          warnings: result.warnings,
          output_path: result.outputPath,
        });
        return 0;
      }
      case "patch": {
        const patchesFlag = flags.get("patches");
        if (typeof patchesFlag !== "string") {
          process.stderr.write("缺少 --patches JSON 参数\n");
          return 2;
        }
        const patches = JSON.parse(patchesFlag) as { fileOffset: number; bytes: string; reason: string }[];
        const outFlag = flags.get("out");
        const outputPath = typeof outFlag === "string" ? resolve(outFlag) : null;
        const result = patchFile(target ?? "", patches, outputPath);
        printJson({
          applied: result.applied,
          rejected: result.rejected,
          sha256_before: result.sha256Before,
          sha256_after: result.sha256After,
          output_path: result.outputPath,
        });
        return 0;
      }
      default:
        process.stderr.write(`未知命令: ${effective}\n${USAGE}`);
        return 2;
    }
  } catch (error) {
    process.stderr.write(`执行失败: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
};

export const run = async (): Promise<void> => {
  process.exitCode = await main(process.argv.slice(2));
};

if (process.argv[1] !== undefined && process.argv[1].endsWith("cli.js")) {
  void run();
}
