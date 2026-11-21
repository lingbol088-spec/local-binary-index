/**
 * 保护特征识别：签名命中 + 结构启发式，输出可复核证据与处置路线。
 */
import type { PeImage } from "../pe/peFile.js";
import { hexBytes, indexOfAll, toHex } from "../util/bytes.js";
import { PACKER_SIGNATURES, type PackerCategory, type PackerSignature } from "./signatures.js";

export interface PackerSignal {
  readonly kind: "section-name" | "section-prefix" | "ascii-marker" | "byte-pattern" | "overlay-marker" | "structural";
  readonly detail: string;
  readonly weight: number;
  readonly rva?: number;
  readonly fileOffset?: number;
  readonly bytes?: string;
}

export interface PackerMatch {
  readonly id: string;
  readonly family: string;
  readonly category: PackerCategory;
  readonly difficulty: string;
  readonly confidence: number;
  readonly notes: string;
  readonly signals: readonly PackerSignal[];
  readonly strategy: readonly string[];
}

export type PiercingVerdict = "clean" | "packed" | "protected" | "obfuscated" | "framework" | "installer";

export interface PackerDetection {
  readonly verdict: PiercingVerdict;
  readonly confidence: number;
  readonly primaryFamily: string | null;
  readonly families: readonly PackerMatch[];
  readonly genericScore: number;
  readonly genericSignals: readonly PackerSignal[];
  readonly strategies: readonly string[];
  readonly method: "full";
  readonly limitations: readonly string[];
}

export interface CompiledPattern {
  readonly bytes: readonly { readonly value: number; readonly mask: number }[];
}

/** 编译带掩码的十六进制模式："60 BE ?? ?? 8D 4?" 中的 '?' 为半字节通配。 */
export const compilePattern = (pattern: string): CompiledPattern => {
  const tokens = pattern.trim().split(/\s+/).filter((token) => token.length > 0);
  const bytes: { value: number; mask: number }[] = [];
  for (const token of tokens) {
    if (token.length !== 2) throw new Error(`invalid pattern token ${JSON.stringify(token)}`);
    const high = token[0] === "?" ? null : Number.parseInt(token[0] ?? "", 16);
    const low = token[1] === "?" ? null : Number.parseInt(token[1] ?? "", 16);
    if (high !== null && Number.isNaN(high)) throw new Error(`invalid hex nibble in ${token}`);
    if (low !== null && Number.isNaN(low)) throw new Error(`invalid hex nibble in ${token}`);
    const value = ((high ?? 0) << 4) | (low ?? 0);
    const mask = (high === null ? 0x00 : 0xf0) | (low === null ? 0x00 : 0x0f);
    bytes.push({ value, mask });
  }
  return { bytes };
};

export interface PatternHit {
  readonly offset: number;
  readonly bytes: string;
}

/** 掩码模式扫描；返回受限数量的命中偏移。 */
export const scanPattern = (
  haystack: Uint8Array,
  compiled: CompiledPattern,
  limit = 16,
): readonly PatternHit[] => {
  const hits: PatternHit[] = [];
  const length = compiled.bytes.length;
  if (length === 0 || haystack.length < length) return hits;
  const first = compiled.bytes[0];
  if (!first) return hits;
  for (let offset = 0; offset <= haystack.length - length; offset += 1) {
    const byte = haystack[offset] ?? 0;
    if ((byte & first.mask) !== first.value) continue;
    let matched = true;
    for (let index = 1; index < length; index += 1) {
      const token = compiled.bytes[index];
      if (!token) continue;
      const candidate = haystack[offset + index] ?? 0;
      if ((candidate & token.mask) !== token.value) {
        matched = false;
        break;
      }
    }
    if (matched) {
      hits.push({ offset, bytes: hexBytes(haystack.subarray(offset, offset + length)) });
      if (hits.length >= limit) break;
    }
  }
  return hits;
};

const normalizeSectionName = (name: string): string => name.replace(/\0/g, "").trim();

interface SectionIndex {
  readonly names: readonly string[];
  readonly rvaByName: ReadonlyMap<string, number>;
}

const indexSections = (image: PeImage): SectionIndex => {
  const names: string[] = [];
  const rvaByName = new Map<string, number>();
  for (const section of image.sections) {
    const name = normalizeSectionName(section.name);
    names.push(name);
    if (!rvaByName.has(name)) rvaByName.set(name, section.virtualAddress);
  }
  return { names, rvaByName };
};

const scoreSignature = (
  image: PeImage,
  bytes: Uint8Array,
  signature: PackerSignature,
  sections: SectionIndex,
): PackerMatch | null => {
  const signals: PackerSignal[] = [];

  for (const wanted of signature.sectionNames ?? []) {
    const rva = sections.rvaByName.get(wanted);
    if (rva !== undefined) {
      signals.push({ kind: "section-name", detail: `区段名精确命中 ${wanted}`, weight: 60, rva });
    }
  }
  for (const prefix of signature.sectionPrefixes ?? []) {
    for (const name of sections.names) {
      if (!name.startsWith(prefix)) continue;
      if ((signature.sectionNames ?? []).includes(name)) continue;
      const rva = sections.rvaByName.get(name);
      signals.push({
        kind: "section-prefix",
        detail: `区段名 ${name} 匹配前缀 ${prefix}`,
        weight: 45,
        ...(rva === undefined ? {} : { rva }),
      });
      break;
    }
  }
  for (const marker of signature.asciiMarkers ?? []) {
    const needle = Uint8Array.from(Buffer.from(marker, "latin1"));
    const hits = indexOfAll(bytes, needle, { limit: 4 });
    if (hits.length > 0) {
      const first = hits[0] ?? 0;
      signals.push({
        kind: "ascii-marker",
        detail: `文件内出现标记 ${JSON.stringify(marker)}${hits.length > 1 ? `（${hits.length} 处）` : ""}`,
        weight: 40,
        fileOffset: first,
      });
    }
  }
  for (const pattern of signature.bytePatterns ?? []) {
    const hits = scanPattern(bytes, compilePattern(pattern.pattern), 4);
    const first = hits[0];
    if (first) {
      signals.push({
        kind: "byte-pattern",
        detail: `${pattern.label} @ ${toHex(first.offset)} → ${first.bytes}`,
        weight: 70,
        fileOffset: first.offset,
      });
    }
  }
  if (image.overlay) {
    const overlayBytes = bytes.subarray(image.overlay.offset);
    for (const marker of signature.asciiMarkers ?? []) {
      const needle = Uint8Array.from(Buffer.from(marker, "latin1"));
      if (indexOfAll(overlayBytes, needle, { limit: 1 }).length > 0) {
        signals.push({
          kind: "overlay-marker",
          detail: `overlay 内出现标记 ${JSON.stringify(marker)}`,
          weight: 45,
          fileOffset: image.overlay.offset,
        });
        break;
      }
    }
  }

  if (signals.length === 0) return null;
  const total = signals.reduce((sum, signal) => sum + signal.weight, 0);
  const confidence = Math.min(1, Number((total / 100).toFixed(3)));
  return {
    id: signature.id,
    family: signature.family,
    category: signature.category,
    difficulty: signature.difficulty,
    confidence,
    notes: signature.notes,
    signals,
    strategy: signature.strategy,
  };
};

export const detectPackers = (image: PeImage, bytes: Uint8Array): PackerDetection => {
  const sections = indexSections(image);
  const matches: PackerMatch[] = [];
  for (const signature of PACKER_SIGNATURES) {
    const match = scoreSignature(image, bytes, signature, sections);
    if (match) matches.push(match);
  }
  matches.sort((left, right) => right.confidence - left.confidence);

  const genericSignals: PackerSignal[] = [];
  const addGeneric = (signal: PackerSignal): void => {
    genericSignals.push(signal);
  };

  const executableSections = image.sections.filter((section) => section.flags.executable);
  const importCount = image.imports.reduce((sum, module) => sum + module.functions.length, 0);
  const entrySection = image.sections.find((section) => {
    const span = Math.max(section.virtualSize, section.sizeOfRawData);
    return image.entryPointRva >= section.virtualAddress && image.entryPointRva < section.virtualAddress + span;
  });

  if (entrySection && image.sections.length > 1) {
    const last = image.sections[image.sections.length - 1];
    if (last && entrySection.index === last.index) {
      addGeneric({
        kind: "structural",
        detail: `入口点位于最后一个区段 ${entrySection.name || `#${entrySection.index}`}`,
        weight: 18,
        rva: image.entryPointRva,
      });
    }
    if (entrySection.entropy >= 7.0) {
      addGeneric({
        kind: "structural",
        detail: `入口所在区段熵 ${entrySection.entropy}（stub 自身被压缩/加密）`,
        weight: 12,
        rva: entrySection.virtualAddress,
      });
    }
  }
  const virtualOnly = image.sections.filter((section) => section.sizeOfRawData === 0 && section.virtualSize > 0);
  if (virtualOnly.length > 0) {
    addGeneric({
      kind: "structural",
      detail: `${virtualOnly.length} 个区段只有虚拟大小（解压目标）: ${virtualOnly.map((section) => section.name || `#${section.index}`).join(",")}`,
      weight: 20,
      rva: virtualOnly[0]?.virtualAddress,
    });
  }
  const rwx = image.sections.filter((section) => section.flags.executable && section.flags.writable);
  if (rwx.length > 0) {
    addGeneric({
      kind: "structural",
      detail: `RWX 区段: ${rwx.map((section) => section.name || `#${section.index}`).join(",")}`,
      weight: 14,
      rva: rwx[0]?.virtualAddress,
    });
  }
  if (importCount > 0 && importCount <= 8) {
    addGeneric({
      kind: "structural",
      detail: `导入函数总数仅 ${importCount}（壳把真实导入藏在运行时）`,
      weight: 16,
    });
  }
  if (importCount === 0 && image.entryPointRva !== 0) {
    addGeneric({
      kind: "structural",
      detail: "导入表为空但存在入口点",
      weight: 10,
    });
  }
  if (image.overlay && image.overlay.entropy >= 7.2) {
    addGeneric({
      kind: "structural",
      detail: `overlay ${image.overlay.size} 字节、熵 ${image.overlay.entropy}（压缩/加密负载）`,
      weight: 12,
      fileOffset: image.overlay.offset,
    });
  }
  if (executableSections.length === 1 && image.sections.length >= 3) {
    addGeneric({
      kind: "structural",
      detail: `仅 1 个可执行区段（${executableSections[0]?.name ?? "?"}），其余为数据/空洞`,
      weight: 8,
    });
  }
  for (const anomaly of image.anomalies) {
    if (anomaly.id === "checksum-mismatch") {
      addGeneric({ kind: "structural", detail: "PE 校验和不匹配（被打包器重写过）", weight: 6 });
    }
    if (anomaly.id === "iat-outside-import-section") {
      addGeneric({ kind: "structural", detail: anomaly.detail, weight: 10, ...(anomaly.rva === undefined ? {} : { rva: anomaly.rva }) });
    }
    if (anomaly.id === "high-entropy-section") {
      addGeneric({ kind: "structural", detail: anomaly.detail, weight: 8, ...(anomaly.rva === undefined ? {} : { rva: anomaly.rva }) });
    }
  }

  const genericScore = Math.min(1, Number((genericSignals.reduce((sum, signal) => sum + signal.weight, 0) / 100).toFixed(3)));

  const top = matches[0] ?? null;
  const protector = matches.find((match) => match.category === "protector" || match.category === "virtualizer");
  const obfuscator = matches.find((match) => match.category === "obfuscator");
  const installer = matches.find((match) => match.category === "installer");
  const framework = matches.find((match) => match.category === "framework");

  let verdict: PiercingVerdict = "clean";
  if (installer && installer.confidence >= 0.4) verdict = "installer";
  else if (protector && protector.confidence >= 0.45) verdict = "protected";
  else if (top && top.category === "packer" && top.confidence >= 0.5) verdict = "packed";
  else if (obfuscator && obfuscator.confidence >= 0.4) verdict = "obfuscated";
  else if (framework && framework.confidence >= 0.4) verdict = "framework";
  else if (genericScore >= 0.45) verdict = "packed";

  const strategies: string[] = [];
  for (const match of matches.slice(0, 2)) {
    strategies.push(`【${match.family}】${match.notes}`);
    for (const step of match.strategy) strategies.push(`  - ${step}`);
  }
  if (verdict === "packed" && (top === null || top.category !== "packer")) {
    strategies.push("【通用壳路线】");
    strategies.push("  - 定位 OEP：stub 内 ESP 定律（pushad → 栈顶硬件访问断点）或尾部 push imm32;retn");
    strategies.push("  - 在全内存可执行区段转为 RWX 后 dump（Frida/x64dbg）");
    strategies.push("  - Scylla/自研 IAT 重建，然后修区段表与入口点");
  }
  if (strategies.length === 0) {
    strategies.push("未命中已知壳指纹；按未加壳二进制常规分析（结构、导入、字符串、控制流）");
  }

  const limitations = [
    "签名库是静态指纹：命中说明「有该家族痕迹」，不保证是确切版本",
    "PE 之外的格式（ELF/Mach-O）不在此模块范围内",
    "加密壳的解密后镜像无法离线获得，必须配合运行时 dump（见 runtime 模块）",
  ];

  return {
    verdict,
    confidence: Math.max(top?.confidence ?? 0, genericScore),
    primaryFamily: top?.family ?? (verdict === "packed" ? "generic-packer" : null),
    families: matches,
    genericScore,
    genericSignals,
    strategies,
    method: "full",
    limitations,
  };
};
