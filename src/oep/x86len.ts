/**
 * 极简 x86 / x86-64 指令长度解码器（只求"长度与控制流事实"，不做语义）。
 *
 * 覆盖：legacy 前缀、REX、one-byte map、0F 两字节 map、ModRM/SIB/disp、
 * 立即数宽度；不覆盖：完整 VEX/EVEX 语义（按 ModRM 近似）、x87 细节语义、
 * 指令合法性校验。任何一个无法解码的字节都返回 valid=false，调用方必须停下。
 */

export type ControlFlowKind =
  | "jmp-rel8"
  | "jmp-rel32"
  | "jmp-rm"
  | "jmp-far"
  | "call-rel32"
  | "call-rm"
  | "jcc-rel8"
  | "jcc-rel32"
  | "ret"
  | "ret-imm16"
  | "push-imm8"
  | "push-imm32"
  | "pushad"
  | "popad"
  | "int3"
  | "int-imm8"
  | "rdtsc"
  | "nop"
  | "other";

export interface DecodedInstruction {
  readonly offset: number;
  readonly length: number;
  readonly bytes: string;
  readonly valid: boolean;
  readonly prefixes: readonly string[];
  readonly rex: number | null;
  readonly opcode: number;
  readonly opcodeMap: "one-byte" | "0f" | "0f38" | "0f3a" | "vex2" | "vex3";
  readonly modrm: { readonly mod: number; readonly reg: number; readonly rm: number } | null;
  readonly kind: ControlFlowKind;
  /** 相对跳转落点（buffer 内偏移，可能为负）；间接跳转为 null。 */
  readonly target: number | null;
  readonly immediate: number | null;
  /** jmp/call [disp32] 在 32 位绝对寻址下的内存操作数地址。 */
  readonly memoryAddress: number | null;
}

const LEGACY_PREFIX_BYTES = new Set([0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67]);

const PREFIX_NAMES: Readonly<Record<number, string>> = {
  0xf0: "lock",
  0xf2: "repne",
  0xf3: "rep",
  0x2e: "cs",
  0x36: "ss",
  0x3e: "ds",
  0x26: "es",
  0x64: "fs",
  0x65: "gs",
  0x66: "opsize",
  0x67: "addrsize",
};

/** one-byte map 里需要 ModRM 的 opcode。 */
const oneByteHasModrm = (opcode: number): boolean => {
  if (opcode <= 0x05) return opcode <= 0x03;
  if (opcode <= 0x07) return false;
  if (opcode <= 0x0b) return true;
  if (opcode <= 0x0e) return false;
  if (opcode === 0x0f) return false;
  if (opcode <= 0x13) return true;
  if (opcode <= 0x17) return false;
  if (opcode <= 0x1b) return true;
  if (opcode <= 0x1f) return false;
  if (opcode <= 0x23) return true;
  if (opcode === 0x24 || opcode === 0x25 || opcode === 0x27) return false;
  if (opcode <= 0x2b) return true;
  if (opcode === 0x2c || opcode === 0x2d || opcode === 0x2f) return false;
  if (opcode <= 0x33) return true;
  if (opcode === 0x34 || opcode === 0x35 || opcode === 0x37) return false;
  if (opcode <= 0x3b) return true;
  if (opcode === 0x3c || opcode === 0x3d || opcode === 0x3f) return false;
  if (opcode <= 0x4f) return false; // inc/dec（32 位）或 REX（64 位）
  if (opcode <= 0x5f) return false;
  if (opcode === 0x60 || opcode === 0x61) return false;
  if (opcode === 0x62 || opcode === 0x63) return true;
  if (opcode === 0x68 || opcode === 0x6a) return false;
  if (opcode === 0x69 || opcode === 0x6b) return true;
  if (opcode <= 0x6f) return false;
  if (opcode <= 0x7f) return false;
  if (opcode <= 0x83) return true;
  if (opcode <= 0x8f) return true;
  if (opcode <= 0x9f) return false;
  if (opcode <= 0xa3) return false;
  if (opcode <= 0xa7) return false;
  if (opcode === 0xa8 || opcode === 0xa9) return false;
  if (opcode <= 0xaf) return false;
  if (opcode <= 0xbf) return false;
  if (opcode === 0xc0 || opcode === 0xc1) return true;
  if (opcode === 0xc2 || opcode === 0xc3) return false;
  if (opcode === 0xc4 || opcode === 0xc5) return true; // LES/LDS（64 位下由 VEX 分支先行处理）
  if (opcode === 0xc6 || opcode === 0xc7) return true;
  if (opcode === 0xc8 || opcode === 0xc9) return false;
  if (opcode === 0xca || opcode === 0xcb) return false;
  if (opcode <= 0xcf) return false;
  if (opcode <= 0xd3) return true;
  if (opcode === 0xd4 || opcode === 0xd5 || opcode === 0xd6 || opcode === 0xd7) return false;
  if (opcode <= 0xdf) return true;
  if (opcode <= 0xe7) return false;
  if (opcode === 0xe8 || opcode === 0xe9 || opcode === 0xea || opcode === 0xeb) return false;
  if (opcode <= 0xef) return false;
  if (opcode === 0xf1 || opcode === 0xf4 || opcode === 0xf5) return false;
  if (opcode === 0xf6 || opcode === 0xf7) return true;
  if (opcode <= 0xfd) return false;
  return opcode === 0xfe || opcode === 0xff;
};

const TWO_BYTE_NO_MODRM = new Set([
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37, 0x77, 0xa0, 0xa1,
  0xa2, 0xa8, 0xa9, 0xaa,
]);

const TWO_BYTE_IMM8 = new Set([
  0x0f, 0x70, 0x71, 0x72, 0x73, 0xa4, 0xa5, 0xac, 0xad, 0xba, 0xc2, 0xc4, 0xc5, 0xc6,
]);

export interface DecodeOptions {
  readonly is64: boolean;
  readonly limit?: number;
}

export const decodeInstruction = (
  buffer: Uint8Array,
  start: number,
  options: DecodeOptions,
): DecodedInstruction => {
  const limit = Math.min(options.limit ?? buffer.length, buffer.length);
  const prefixes: string[] = [];
  let cursor = start;
  let operandSizeOverride = false;
  let addressSizeOverride = false;
  let rex: number | null = null;

  const bail = (): DecodedInstruction => ({
    offset: start,
    length: 1,
    bytes: Array.from(buffer.subarray(start, Math.min(start + 16, buffer.length)), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join(""),
    valid: false,
    prefixes,
    rex,
    opcode: buffer[start] ?? 0,
    opcodeMap: "one-byte",
    modrm: null,
    kind: "other",
    target: null,
    immediate: null,
    memoryAddress: null,
  });

  const readByte = (): number | null => {
    if (cursor >= limit) return null;
    const byte = buffer[cursor] ?? 0;
    cursor += 1;
    return byte;
  };
  const peekByte = (): number | null => (cursor < limit ? buffer[cursor] ?? 0 : null);

  for (;;) {
    const byte = peekByte();
    if (byte === null) return bail();
    if (LEGACY_PREFIX_BYTES.has(byte)) {
      prefixes.push(PREFIX_NAMES[byte] ?? `prefix-${byte.toString(16)}`);
      if (byte === 0x66) operandSizeOverride = true;
      if (byte === 0x67) addressSizeOverride = true;
      cursor += 1;
      continue;
    }
    if (options.is64 && byte >= 0x40 && byte <= 0x4f) {
      rex = byte;
      cursor += 1;
      continue;
    }
    break;
  }

  const opcodeByte = readByte();
  if (opcodeByte === null) return bail();
  let opcodeMap: DecodedInstruction["opcodeMap"] = "one-byte";
  let opcode = opcodeByte;

  if (opcodeByte === 0x0f) {
    const second = readByte();
    if (second === null) return bail();
    if (second === 0x38 || second === 0x3a) {
      const third = readByte();
      if (third === null) return bail();
      opcodeMap = second === 0x38 ? "0f38" : "0f3a";
      opcode = third;
    } else {
      opcodeMap = "0f";
      opcode = second;
    }
  } else if (options.is64 && (opcodeByte === 0xc4 || opcodeByte === 0xc5)) {
    const extra = opcodeByte === 0xc4 ? 2 : 1;
    for (let index = 0; index < extra; index += 1) {
      if (readByte() === null) return bail();
    }
    opcodeMap = opcodeByte === 0xc4 ? "vex3" : "vex2";
    const nextOpcode = readByte();
    if (nextOpcode === null) return bail();
    opcode = nextOpcode;
  }

  const hasRexW = rex !== null && (rex & 0x08) !== 0;
  const operandSize = options.is64
    ? hasRexW
      ? 8
      : operandSizeOverride
        ? 2
        : 4
    : operandSizeOverride
      ? 2
      : 4;

  let needsModrm = false;
  let immediateSize = 0;
  let kind: ControlFlowKind = "other";
  let immediate: number | null = null;

  if (opcodeMap === "one-byte") {
    needsModrm = oneByteHasModrm(opcode);
    switch (opcode) {
      case 0x60:
        kind = "pushad";
        break;
      case 0x61:
        kind = "popad";
        break;
      case 0x68:
        immediateSize = operandSize === 2 ? 2 : 4;
        kind = "push-imm32";
        break;
      case 0x6a:
        immediateSize = 1;
        kind = "push-imm8";
        break;
      case 0xa8:
        immediateSize = 1;
        break;
      case 0xa9:
        immediateSize = operandSize;
        break;
      case 0xc2:
        immediateSize = 2;
        kind = "ret-imm16";
        break;
      case 0xc3:
        kind = "ret";
        break;
      case 0xca:
        immediateSize = 2;
        break;
      case 0xcb:
        kind = "ret";
        break;
      case 0xcc:
        kind = "int3";
        break;
      case 0xcd:
        immediateSize = 1;
        kind = "int-imm8";
        break;
      case 0x90:
        kind = "nop";
        break;
      case 0xe8:
        immediateSize = 4;
        kind = "call-rel32";
        break;
      case 0xe9:
        immediateSize = 4;
        kind = "jmp-rel32";
        break;
      case 0xea:
        immediateSize = 6;
        kind = "jmp-far";
        break;
      case 0xeb:
        immediateSize = 1;
        kind = "jmp-rel8";
        break;
      case 0xc8:
        immediateSize = 3;
        break;
      case 0xd4:
      case 0xd5:
      case 0xe4:
      case 0xe5:
      case 0xe6:
      case 0xe7:
      case 0x80:
      case 0x82:
      case 0x83:
      case 0xc0:
      case 0xc1:
      case 0xc6:
      case 0xf6:
        immediateSize = 1;
        break;
      case 0x81:
      case 0xc7:
      case 0xf7:
        immediateSize = operandSize === 2 ? 2 : 4;
        break;
      case 0xa0:
      case 0xa1:
      case 0xa2:
      case 0xa3:
        immediateSize = options.is64 ? 8 : addressSizeOverride ? 2 : 4;
        break;
      default:
        if (opcode >= 0x70 && opcode <= 0x7f) {
          immediateSize = 1;
          kind = "jcc-rel8";
        } else if (opcode >= 0xb0 && opcode <= 0xb7) {
          immediateSize = 1; // mov r8, imm8
        } else if (opcode >= 0xb8 && opcode <= 0xbf) {
          immediateSize = operandSize === 2 ? 2 : 4; // mov r32, imm32
        }
        break;
    }
  } else if (opcodeMap === "0f") {
    needsModrm = !TWO_BYTE_NO_MODRM.has(opcode);
    if (TWO_BYTE_IMM8.has(opcode)) immediateSize = 1;
    if (opcode >= 0x80 && opcode <= 0x8f) {
      immediateSize = 4;
      kind = "jcc-rel32";
      needsModrm = false;
    }
    if (opcode === 0x31) kind = "rdtsc";
  } else {
    needsModrm = true;
    if (opcodeMap === "0f3a") immediateSize = 1;
  }

  let modrm: DecodedInstruction["modrm"] = null;
  let memoryAddress: number | null = null;

  if (needsModrm) {
    const byte = readByte();
    if (byte === null) return bail();
    const mod = (byte >> 6) & 0x03;
    const reg = (byte >> 3) & 0x07;
    const rm = byte & 0x07;
    modrm = { mod, reg, rm };

    if (opcodeMap === "one-byte" && opcode === 0xff) {
      if (reg === 4) kind = "jmp-rm";
      else if (reg === 2 || reg === 3) kind = "call-rm";
    }

    if (mod !== 3) {
      let dispSize = 0;
      let absoluteDisp32 = false;
      if (addressSizeOverride && !options.is64) {
        if (mod === 0 && rm === 6) dispSize = 2;
        else if (mod === 1) dispSize = 1;
        else if (mod === 2) dispSize = 2;
      } else if (rm === 4) {
        const sib = readByte();
        if (sib === null) return bail();
        const sibBase = sib & 0x07;
        if (mod === 0 && sibBase === 5) dispSize = 4;
        else if (mod === 1) dispSize = 1;
        else if (mod === 2) dispSize = 4;
      } else if (mod === 0 && rm === 5) {
        dispSize = 4;
        absoluteDisp32 = !options.is64;
      } else if (mod === 1) {
        dispSize = 1;
      } else if (mod === 2) {
        dispSize = 4;
      }

      const dispStart = cursor;
      for (let index = 0; index < dispSize; index += 1) {
        if (readByte() === null) return bail();
      }
      if (absoluteDisp32 && dispSize === 4) {
        memoryAddress =
          ((buffer[dispStart] ?? 0) |
            ((buffer[dispStart + 1] ?? 0) << 8) |
            ((buffer[dispStart + 2] ?? 0) << 16) |
            ((buffer[dispStart + 3] ?? 0) << 24)) >>>
          0;
      }
    }
  }

  let relTarget: number | null = null;
  if (immediateSize > 0) {
    let value = 0;
    for (let index = 0; index < immediateSize; index += 1) {
      const byte = readByte();
      if (byte === null) return bail();
      value |= byte << (index * 8);
    }
    const unsigned = value >>> 0;
    if (kind === "push-imm32" || kind === "push-imm8" || kind === "ret-imm16") immediate = unsigned;
    if (kind === "jmp-rel8" || kind === "jcc-rel8") {
      relTarget = cursor + ((unsigned << 24) >> 24);
    } else if (kind === "jmp-rel32" || kind === "jcc-rel32" || kind === "call-rel32") {
      relTarget = cursor + (unsigned | 0);
    }
  }

  const length = cursor - start;
  if (length <= 0 || length > 16 || start + length > limit) return bail();

  const bytes = Array.from(buffer.subarray(start, start + length), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");

  return {
    offset: start,
    length,
    bytes,
    valid: true,
    prefixes,
    rex,
    opcode,
    opcodeMap,
    modrm,
    kind,
    target: relTarget,
    immediate,
    memoryAddress,
  };
};

/** 顺序解码一个窗口，返回指令序列（遇到非法字节立即停）。 */
export const decodeWindow = (
  buffer: Uint8Array,
  start: number,
  end: number,
  options: DecodeOptions,
  maxInstructions = 20_000,
): DecodedInstruction[] => {
  const out: DecodedInstruction[] = [];
  let cursor = Math.max(0, start);
  const limit = Math.min(end, options.limit ?? buffer.length);
  while (cursor < limit && out.length < maxInstructions) {
    const instruction = decodeInstruction(buffer, cursor, { is64: options.is64, limit });
    out.push(instruction);
    if (!instruction.valid) break;
    cursor += instruction.length;
  }
  return out;
};
