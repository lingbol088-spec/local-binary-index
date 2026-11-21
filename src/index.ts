/**
 * 统一编排：一次读盘 → 结构解析 → 保护识别 → 入口转移 → 导入重建 → 反分析 → 托管层 → 脚本。
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { loadFile, sha256Bytes, toHex } from "./util/bytes.js";
import { parsePe, type PeImage } from "./pe/peFile.js";
import { detectPackers, type PackerDetection } from "./packer/detect.js";
import { huntOep, type HuntOepOptions, type OepHuntResult } from "./oep/hunt.js";
import { planIatRebuild, type IatPlanResult } from "./iat/plan.js";
import { scanAntiAnalysis, buildPatchList, type AntiAnalysisResult } from "./antidebug/scan.js";
import { analyzeManaged, type ManagedProtectionReport } from "./dotnet/managed.js";
import { emitScripts, type ScriptBundle } from "./runtime/scripts.js";
import { repairImageDump, applyBytePatches, type DumpRepairResult, type PatchApplyResult, type BytePatch } from "./runtime/fixDump.js";
import { PRODUCT_ID, PRODUCT_VERSION } from "./activation.js";

export interface EvidenceRef {
  readonly id: string;
  readonly kind: string;
  readonly detail: string;
  readonly digest: string;
}

export interface ImageSummary {
  readonly is64: boolean;
  readonly machine: string;
  readonly subsystem: string;
  readonly imageBase: number;
  readonly entryPoint: { readonly rva: number; readonly va: number };
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly sectionAlignment: number;
  readonly fileAlignment: number;
  readonly checksumValid: boolean;
  readonly dllCharacteristics: number;
  readonly sections: readonly {
    readonly index: number;
    readonly name: string;
    readonly virtualAddress: number;
    readonly virtualSize: number;
    readonly sizeOfRawData: number;
    readonly pointerToRawData: number;
    readonly entropy: number;
    readonly flags: string;
    readonly truncated: boolean;
  }[];
  readonly dataDirectories: readonly { readonly name: string; readonly rva: number; readonly size: number }[];
  readonly importCount: { readonly modules: number; readonly functions: number };
  readonly exports: number;
  readonly resources: readonly string[];
  readonly tls: { readonly callbacks: readonly number[] } | null;
  readonly debug: readonly { readonly type: string; readonly pdbPath: string | null }[];
  readonly overlay: { readonly offset: number; readonly size: number; readonly entropy: number; readonly markers: readonly string[] } | null;
  readonly richHeaderEntries: number;
  readonly clr: boolean;
  readonly anomalies: readonly { readonly id: string; readonly severity: string; readonly detail: string }[];
}

export interface BinaryAnalysis {
  readonly source: { readonly path: string | null; readonly size: number; readonly sha256: string; readonly analyzed_at: string };
  readonly product: { readonly id: string; readonly version: string };
  readonly image: ImageSummary;
  readonly protection: PackerDetection;
  readonly entryTransfer: OepHuntResult;
  readonly imports: IatPlanResult;
  readonly antiAnalysis: AntiAnalysisResult;
  readonly managed: ManagedProtectionReport;
  readonly scripts: ScriptBundle;
  readonly patchList: readonly { readonly fileOffset: number; readonly bytes: string; readonly reason: string }[];
  readonly evidence: readonly EvidenceRef[];
  readonly limitations: readonly string[];
}

const summarizeImage = (image: PeImage): ImageSummary => ({
  is64: image.is64,
  machine: image.machineName,
  subsystem: image.subsystemName,
  imageBase: image.imageBase,
  entryPoint: { rva: image.entryPointRva, va: image.entryPointVa },
  sizeOfImage: image.sizeOfImage,
  sizeOfHeaders: image.sizeOfHeaders,
  sectionAlignment: image.sectionAlignment,
  fileAlignment: image.fileAlignment,
  checksumValid: image.checksumValid,
  dllCharacteristics: image.dllCharacteristics,
  sections: image.sections.map((section) => ({
    index: section.index,
    name: section.name,
    virtualAddress: section.virtualAddress,
    virtualSize: section.virtualSize,
    sizeOfRawData: section.sizeOfRawData,
    pointerToRawData: section.pointerToRawData,
    entropy: section.entropy,
    flags: [
      section.flags.executable ? "X" : "-",
      section.flags.writable ? "W" : "-",
      section.flags.readable ? "R" : "-",
      section.flags.code ? "C" : "-",
    ].join(""),
    truncated: section.truncated,
  })),
  dataDirectories: image.dataDirectories.map((directory) => ({
    name: directory.name,
    rva: directory.rva,
    size: directory.size,
  })),
  importCount: {
    modules: image.imports.length,
    functions: image.imports.reduce((sum, module) => sum + module.functions.length, 0),
  },
  exports: image.exports.length,
  resources: image.resources.map((resource) => resource.declaredName),
  tls: image.tls ? { callbacks: image.tls.callbackVas } : null,
  debug: image.debug.map((entry) => ({ type: entry.typeName, pdbPath: entry.pdbPath })),
  overlay: image.overlay
    ? {
        offset: image.overlay.offset,
        size: image.overlay.size,
        entropy: image.overlay.entropy,
        markers: image.overlay.markers,
      }
    : null,
  richHeaderEntries: image.richHeader?.entries.length ?? 0,
  clr: image.clrRuntime !== null,
  anomalies: image.anomalies.map((anomaly) => ({
    id: anomaly.id,
    severity: anomaly.severity,
    detail: anomaly.detail,
  })),
});

const buildEvidence = (image: PeImage, protection: PackerDetection): EvidenceRef[] => {
  const evidence: EvidenceRef[] = [
    {
      id: "E-001",
      kind: "sample",
      detail: `样本 ${image.source.path ?? "<memory>"}（${image.source.size} 字节）`,
      digest: image.source.sha256,
    },
    {
      id: "E-002",
      kind: "pe-structure",
      detail: `${image.machineName} / ${image.subsystemName} / ${image.sections.length} 区段 / 入口 ${toHex(image.entryPointVa, 16)}`,
      digest: image.source.sha256,
    },
    {
      id: "E-003",
      kind: "protection",
      detail: `${protection.verdict} · ${protection.primaryFamily ?? "无已知家族"} · 置信度 ${protection.confidence}`,
      digest: image.source.sha256,
    },
  ];
  for (const section of image.sections) {
    evidence.push({
      id: `E-${String(evidence.length + 1).padStart(3, "0")}`,
      kind: "section",
      detail: `${section.name || `#${section.index}`} @ RVA ${toHex(section.virtualAddress)} raw ${section.sizeOfRawData} entropy ${section.entropy}`,
      digest: sha256Bytes(
        new Uint8Array(
          Buffer.from(image.binaryReader.buffer.buffer, image.binaryReader.buffer.byteOffset + section.pointerToRawData, section.availableRawBytes),
        ),
      ),
    });
  }
  return evidence;
};

export interface AnalyzeOptions extends HuntOepOptions {
  readonly now?: string;
}

export const analyzeBytes = (bytes: Uint8Array, label: string, options: AnalyzeOptions = {}): BinaryAnalysis => {
  const image = parsePe(bytes, { path: label === "<memory>" ? null : label });
  const protection = detectPackers(image, bytes);
  const entryTransfer = huntOep(image, bytes, options);
  const imports = planIatRebuild(image, bytes);
  const antiAnalysis = scanAntiAnalysis(image, bytes);
  const managed = analyzeManaged(image, bytes);
  const scripts = emitScripts({ image, oep: entryTransfer, iat: imports, anti: antiAnalysis, packer: protection });
  const patchList = buildPatchList(antiAnalysis);
  const evidence = buildEvidence(image, protection);

  const limitations = [
    ...protectorLimitations(protection),
    ...entryTransfer.limitations,
    ...imports.limitations,
    ...antiAnalysis.limitations,
    ...managed.limitations,
    "静态结论不执行样本；加密壳的真实镜像只能由运行时 dump 提供",
  ];

  return {
    source: {
      path: image.source.path,
      size: image.source.size,
      sha256: image.source.sha256,
      analyzed_at: options.now ?? new Date().toISOString(),
    },
    product: { id: PRODUCT_ID, version: PRODUCT_VERSION },
    image: summarizeImage(image),
    protection,
    entryTransfer,
    imports,
    antiAnalysis,
    managed,
    scripts,
    patchList,
    evidence,
    limitations,
  };
};

const protectorLimitations = (protection: PackerDetection): readonly string[] =>
  protection.verdict === "protected" ? protection.limitations : [];

export const analyzeFile = (path: string, options: AnalyzeOptions = {}): BinaryAnalysis => {
  const loaded = loadFile(path);
  const analysis = analyzeBytes(loaded.bytes, path, options);
  return {
    ...analysis,
    source: { ...analysis.source, sha256: loaded.sha256, size: loaded.size, path },
  };
};

export interface RepairResult extends DumpRepairResult {
  readonly outputPath: string | null;
}

export const repairDumpFile = (path: string, outputPath: string | null = null): RepairResult => {
  const bytes = new Uint8Array(readFileSync(path));
  const repaired = repairImageDump(bytes);
  if (outputPath) {
    writeFileSync(outputPath, repaired.output);
  }
  return { ...repaired, outputPath };
};

export const patchFile = (path: string, patches: readonly BytePatch[], outputPath: string | null = null): PatchApplyResult & { outputPath: string | null } => {
  const bytes = new Uint8Array(readFileSync(path));
  const result = applyBytePatches(bytes, patches);
  if (outputPath) writeFileSync(outputPath, result.output);
  return { ...result, outputPath };
};

export const writeScripts = (analysis: BinaryAnalysis, outDirectory: string): readonly string[] => {
  mkdirSync(outDirectory, { recursive: true });
  const files: { name: string; content: string }[] = [
    { name: "recover.x64dbg.txt", content: analysis.scripts.x64dbg },
    { name: "recover.gdb.txt", content: analysis.scripts.gdb },
    { name: "recover.windbg.txt", content: analysis.scripts.windbg },
    { name: "recover.frida.js", content: analysis.scripts.frida },
    { name: "rebuild.scylla.txt", content: analysis.scripts.scylla.join("\n") },
    { name: "patches.txt", content: analysis.patchList.map((patch) => `${toHex(patch.fileOffset)}: ${patch.bytes}\t${patch.reason}`).join("\n") },
  ];
  const written: string[] = [];
  for (const file of files) {
    const target = join(outDirectory, file.name);
    writeFileSync(target, `${file.content}\n`, "utf8");
    written.push(target);
  }
  return written;
};

export * from "./pe/peFile.js";
export * from "./packer/detect.js";
export * from "./packer/signatures.js";
export * from "./oep/hunt.js";
export * from "./oep/x86len.js";
export * from "./iat/plan.js";
export * from "./antidebug/scan.js";
export * from "./dotnet/managed.js";
export * from "./runtime/scripts.js";
export * from "./runtime/fixDump.js";
export * from "./report/markdown.js";
export * from "./activation.js";
