/**
 * OEP（原始入口点）猎人。
 *
 * 静态路线：从入口 stub 顺序解码，抓三类可判定转移：
 *   1. 尾部 `push <VA>; retn`（UPX 系经典 tail jump）
 *   2. 相对 jmp 跳到入口区段之外（解压完成后跳回原代码）
 *   3. popad 之后的第一条相对跳转（解压循环收尾）
 * 运行时路线：ESP 定律、寄存器/内存间接转移、内存 dump 的断点命令。
 */
import type { PeImage, PeSection } from "../pe/peFile.js";
import { makeRvaResolver } from "../pe/peFile.js";
import { decodeInstruction, type DecodedInstruction } from "./x86len.js";
import { hexBytes, toHex } from "../util/bytes.js";

export type OepOrigin = "push-ret" | "jmp-rel" | "popad-jmp" | "internal-jmp";

export interface OepCandidate {
  readonly rva: number;
  readonly va: number;
  readonly origin: OepOrigin;
  readonly score: number;
  readonly resolvable: boolean;
  readonly sectionName: string | null;
  readonly evidence: readonly string[];
  readonly instructionFileOffset: number;
  readonly instructionBytes: string;
}

export interface OepBreakpoint {
  readonly kind: "oep-candidate" | "indirect-transfer" | "esp-law";
  readonly va: number;
  readonly rva: number;
  readonly note: string;
  readonly x64dbg: string;
  readonly gdb: string;
  readonly windbg: string;
}

export interface OepHuntResult {
  readonly entry: {
    readonly rva: number;
    readonly va: number;
    readonly fileOffset: number | null;
    readonly sectionIndex: number | null;
    readonly sectionName: string | null;
    readonly sectionEntropy: number | null;
    readonly firstBytes: string;
  };
  readonly stub: {
    readonly decodedInstructions: number;
    readonly stoppedReason: string;
    readonly pushadOffset: number | null;
    readonly popadOffset: number | null;
    readonly callPopIdiom: boolean;
    readonly controlTransfers: number;
  };
  readonly candidates: readonly OepCandidate[];
  readonly best: OepCandidate | null;
  readonly indirectTransfers: readonly { readonly fileOffset: number; readonly va: number | null; readonly note: string }[];
  readonly espLaw: { readonly applicable: boolean; readonly reason: string; readonly commands: readonly string[] };
  readonly breakpoints: readonly OepBreakpoint[];
  readonly instructions: readonly DecodedInstruction[];
  readonly limitations: readonly string[];
}

export interface HuntOepOptions {
  readonly maxInstructions?: number;
  readonly includeInternalJumps?: boolean;
}

const sectionLabel = (section: PeSection | null): string | null =>
  section ? section.name || `#${section.index}` : null;

/** 从 from 开始最多看 limit 条指令，找第一条 ret/ret imm16。 */
const scanForRet = (
  bytes: Uint8Array,
  from: number,
  end: number,
  is64: boolean,
  limit: number,
): DecodedInstruction | null => {
  let cursor = from;
  for (let index = 0; index < limit && cursor < end; index += 1) {
    const instruction = decodeInstruction(bytes, cursor, { is64, limit: end });
    if (!instruction.valid) return null;
    if (instruction.kind === "ret" || instruction.kind === "ret-imm16") return instruction;
    cursor += instruction.length;
  }
  return null;
};

export const huntOep = (image: PeImage, bytes: Uint8Array, options: HuntOepOptions = {}): OepHuntResult => {
  const resolver = makeRvaResolver(image);
  const entrySection = resolver.sectionForRva(image.entryPointRva);
  const entryOffset = resolver.rvaToOffset(image.entryPointRva);
  const maxInstructions = options.maxInstructions ?? 20_000;

  const limitations: string[] = [
    "静态 stub 走查无法解析间接跳转（jmp reg / jmp [mem]）的真实目标，只给运行时断点",
    "加壳器常插入垃圾字节或花指令，遇到非法指令立即停止（看 stoppedReason）",
    "x86-64 的 VEX/EVEX 只按长度近似解码，个别指令可能错位",
    "候选是「最值得下断的位置」，不是脱壳成功的证明——必须运行时 dump 验证",
  ];

  if (entryOffset === null || !entrySection) {
    return {
      entry: {
        rva: image.entryPointRva,
        va: image.entryPointVa,
        fileOffset: null,
        sectionIndex: entrySection?.index ?? null,
        sectionName: sectionLabel(entrySection),
        sectionEntropy: entrySection?.entropy ?? null,
        firstBytes: "",
      },
      stub: {
        decodedInstructions: 0,
        stoppedReason: "entry-unmapped",
        pushadOffset: null,
        popadOffset: null,
        callPopIdiom: false,
        controlTransfers: 0,
      },
      candidates: [],
      best: null,
      indirectTransfers: [],
      espLaw: { applicable: false, reason: "入口点无法映射到文件偏移，无法走查 stub", commands: [] },
      breakpoints: [],
      instructions: [],
      limitations,
    };
  }

  const windowEnd = Math.min(bytes.length, entrySection.pointerToRawData + entrySection.availableRawBytes);
  const instructions: DecodedInstruction[] = [];
  let stoppedReason = "section-end";
  let cursor = entryOffset;
  let pushadOffset: number | null = null;
  let popadOffset: number | null = null;
  let callPopIdiom = false;
  let controlTransfers = 0;

  while (cursor < windowEnd && instructions.length < maxInstructions) {
    const instruction = decodeInstruction(bytes, cursor, { is64: image.is64, limit: windowEnd });
    instructions.push(instruction);
    if (!instruction.valid) {
      stoppedReason = `invalid-instruction@${toHex(cursor)}`;
      break;
    }
    cursor += instruction.length;

    if (instruction.kind === "pushad" && pushadOffset === null) pushadOffset = instruction.offset;
    if (instruction.kind === "popad") popadOffset = instruction.offset;
    if (instruction.kind === "call-rel32" && instruction.target === instruction.offset + instruction.length) {
      callPopIdiom = true;
    }
    if (
      instruction.kind === "jmp-rel8" ||
      instruction.kind === "jmp-rel32" ||
      instruction.kind === "jmp-rm" ||
      instruction.kind === "jmp-far" ||
      instruction.kind === "ret" ||
      instruction.kind === "ret-imm16"
    ) {
      controlTransfers += 1;
    }
  }
  if (instructions.length >= maxInstructions) stoppedReason = "instruction-budget";

  const candidates: OepCandidate[] = [];
  const seen = new Map<number, OepCandidate>();
  const indirectTransfers: { fileOffset: number; va: number | null; note: string }[] = [];

  const sectionBaseRva = entrySection.virtualAddress;
  const sectionBaseOffset = entrySection.pointerToRawData;
  const localOffsetToRva = (offset: number): number | null => {
    if (offset < sectionBaseOffset || offset >= sectionBaseOffset + entrySection.availableRawBytes) return null;
    return sectionBaseRva + (offset - sectionBaseOffset);
  };

  const record = (origin: OepOrigin, instruction: DecodedInstruction, targetRva: number, evidence: string[]): void => {
    const targetSection = resolver.sectionForRva(targetRva);
    const resolvable = targetRva > 0 && targetRva < image.sizeOfImage;
    let score = origin === "push-ret" ? 58 : origin === "popad-jmp" ? 50 : origin === "jmp-rel" ? 40 : 10;
    if (resolvable) score += 12;
    if (targetSection && targetSection.index !== entrySection.index) score += 20;
    else score -= 28;
    if (targetSection?.flags.executable) score += 14;
    if (targetSection && targetSection.entropy < entrySection.entropy - 0.4) score += 8;
    if (targetRva % 16 === 0) score += 6;
    if (targetRva === image.entryPointRva) score -= 40;
    const clamped = Math.max(0, Math.min(100, score));
    if (clamped <= 0) return;

    const candidate: OepCandidate = {
      rva: targetRva,
      va: image.imageBase + targetRva,
      origin,
      score: clamped,
      resolvable,
      sectionName: sectionLabel(targetSection),
      evidence: [
        ...evidence,
        `来源指令 @ ${toHex(instruction.offset)}: ${instruction.bytes}`,
        `目标区段 ${sectionLabel(targetSection) ?? "未映射"}（熵 ${targetSection ? targetSection.entropy : "?"}，入口区段熵 ${entrySection.entropy}）`,
      ],
      instructionFileOffset: instruction.offset,
      instructionBytes: instruction.bytes,
    };
    const existing = seen.get(targetRva);
    if (!existing) {
      seen.set(targetRva, candidate);
      candidates.push(candidate);
      return;
    }
    if (candidate.score > existing.score) {
      seen.set(targetRva, { ...candidate, evidence: [...candidate.evidence, ...existing.evidence] });
      const index = candidates.findIndex((entry) => entry.rva === targetRva);
      if (index >= 0) candidates[index] = seen.get(targetRva) ?? candidate;
    } else {
      const index = candidates.findIndex((entry) => entry.rva === targetRva);
      if (index >= 0) candidates[index] = { ...existing, evidence: [...existing.evidence, ...candidate.evidence] };
    }
  };

  for (let index = 0; index < instructions.length; index += 1) {
    const instruction = instructions[index];
    if (!instruction || !instruction.valid) continue;
    const next = instructions[index + 1];

    if (instruction.kind === "push-imm32" && instruction.immediate !== null) {
      const ret = scanForRet(bytes, instruction.offset + instruction.length, windowEnd, image.is64, 6);
      if (ret) {
        const immediate = instruction.immediate;
        const rva = immediate >= image.imageBase ? immediate - image.imageBase : immediate;
        record("push-ret", instruction, rva, [
          `尾部跳转惯用法 push ${toHex(immediate)} ; ret（ret @ ${toHex(ret.offset)}）`,
          immediate >= image.imageBase
            ? "立即数按 VA 解释（>= ImageBase）"
            : "立即数按 RVA 解释（< ImageBase）",
        ]);
      }
    }

    if (instruction.kind === "jmp-rel8" || instruction.kind === "jmp-rel32") {
      if (instruction.target !== null) {
        const targetRva = localOffsetToRva(instruction.target);
        if (targetRva !== null) {
          if (options.includeInternalJumps) {
            record("internal-jmp", instruction, targetRva, ["相对跳转仍落在入口区段内（多为解压循环）"]);
          }
        } else {
          const mapped = resolver.offsetToRva(instruction.target);
          if (mapped !== null) {
            record("jmp-rel", instruction, mapped, [
              `相对跳转跨出入口区段 → 目标文件偏移 ${toHex(instruction.target)}`,
            ]);
          }
        }
      }
    }

    if (instruction.kind === "jmp-rm") {
      const note = instruction.modrm?.mod === 3
        ? "jmp reg（寄存器间接跳转，stub 出口）— 命中后读目标寄存器即 OEP"
        : instruction.memoryAddress !== null
          ? `jmp [${toHex(instruction.memoryAddress)}]（绝对内存间接跳转）— 命中后读该槽位的值`
          : "jmp [mem]（基址/RIP 相对）— 命中后读操作数";
      indirectTransfers.push({
        fileOffset: instruction.offset,
        va: (() => {
          const rva = resolver.offsetToRva(instruction.offset);
          return rva === null ? null : image.imageBase + rva;
        })(),
        note,
      });
    }

    if (instruction.kind === "popad" && next && (next.kind === "jmp-rel8" || next.kind === "jmp-rel32")) {
      const mapped =
        next.target === null ? null : localOffsetToRva(next.target) ?? resolver.offsetToRva(next.target) ?? null;
      if (mapped !== null) {
        record("popad-jmp", next, mapped, ["popad 之后的第一条相对跳转（解压循环收尾）"]);
      }
    }
  }

  candidates.sort((left, right) => right.score - left.score);
  const best = candidates[0] ?? null;

  const espLaw = pushadOffset !== null
    ? {
        applicable: true,
        reason: `stub @ ${toHex(pushadOffset)} 出现 pushad：解压器先把 8 个寄存器压栈，解压完由 popad 读回；对 ESP 指向的栈槽下硬件访问断点，命中即接近 OEP`,
        commands: [
          "x64dbg: 断在 pushad 之后 → `r esp` 记下栈值 → `hr <esp值>` → F9",
          "gdb:    `b *<pushad_va>` 命中后 `watch *(unsigned long*)$rsp` → `c`",
          "WinDbg: `ba r 1 @esp` → `g`",
        ],
      }
    : {
        applicable: false,
        reason: "stub 内未见 pushad（x64 常见），改用间接转移断点或内存写断点路线",
        commands: [],
      };

  const breakpoints: OepBreakpoint[] = [];
  for (const candidate of candidates.slice(0, 5)) {
    breakpoints.push({
      kind: "oep-candidate",
      va: candidate.va,
      rva: candidate.rva,
      note: `${candidate.origin} 候选，得分 ${candidate.score}`,
      x64dbg: `bp ${toHex(candidate.va, 16)}`,
      gdb: `b *${toHex(candidate.va, 16)}`,
      windbg: `bp ${toHex(candidate.va, 16)}`,
    });
  }
  for (const transfer of indirectTransfers.slice(0, 4)) {
    if (transfer.va === null) continue;
    breakpoints.push({
      kind: "indirect-transfer",
      va: transfer.va,
      rva: transfer.va - image.imageBase,
      note: transfer.note,
      x64dbg: `bp ${toHex(transfer.va, 16)}`,
      gdb: `b *${toHex(transfer.va, 16)}`,
      windbg: `bp ${toHex(transfer.va, 16)}`,
    });
  }
  if (pushadOffset !== null) {
    const pushadRva = resolver.offsetToRva(pushadOffset);
    if (pushadRva !== null) {
      const pushadVa = image.imageBase + pushadRva;
      breakpoints.push({
        kind: "esp-law",
        va: pushadVa,
        rva: pushadRva,
        note: "ESP 定律入口：pushad 之后对栈顶下硬件访问断点",
        x64dbg: `bp ${toHex(pushadVa, 16)}`,
        gdb: `b *${toHex(pushadVa, 16)}`,
        windbg: `bp ${toHex(pushadVa, 16)}`,
      });
    }
  }

  return {
    entry: {
      rva: image.entryPointRva,
      va: image.entryPointVa,
      fileOffset: entryOffset,
      sectionIndex: entrySection.index,
      sectionName: sectionLabel(entrySection),
      sectionEntropy: entrySection.entropy,
      firstBytes: hexBytes(bytes.subarray(entryOffset, entryOffset + 32)),
    },
    stub: {
      decodedInstructions: instructions.length,
      stoppedReason,
      pushadOffset,
      popadOffset,
      callPopIdiom,
      controlTransfers,
    },
    candidates,
    best,
    indirectTransfers,
    espLaw,
    breakpoints,
    instructions,
    limitations,
  };
};
