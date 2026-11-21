/**
 * 字节层：边界安全的读写器、熵、摘要、hex。
 * 零依赖，只用 node: 内置模块。
 */
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";

export class ByteReader {
  readonly buffer: Uint8Array;

  constructor(buffer: Uint8Array) {
    this.buffer = buffer;
  }

  get length(): number {
    return this.buffer.length;
  }

  has(offset: number, size = 1): boolean {
    return Number.isInteger(offset) && offset >= 0 && size >= 0 && offset + size <= this.buffer.length;
  }

  u8(offset: number): number {
    if (!this.has(offset)) return 0;
    return this.buffer[offset] ?? 0;
  }

  u16(offset: number): number {
    if (!this.has(offset, 2)) return 0;
    return (this.u8(offset) | (this.u8(offset + 1) << 8)) >>> 0;
  }

  u32(offset: number): number {
    if (!this.has(offset, 4)) return 0;
    return (
      (this.u8(offset) |
        (this.u8(offset + 1) << 8) |
        (this.u8(offset + 2) << 16) |
        (this.u8(offset + 3) << 24)) >>>
      0
    );
  }

  i32(offset: number): number {
    return this.u32(offset) | 0;
  }

  u64(offset: number): bigint {
    const low = BigInt(this.u32(offset));
    const high = BigInt(this.u32(offset + 4));
    return (high << 32n) | low;
  }

  /** 按镜像位宽读取一个 RVA/VA 槽位（4 或 8 字节），统一返回 number。 */
  ptr(offset: number, is64: boolean): number {
    if (!is64) return this.u32(offset);
    const value = this.u64(offset);
    return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
  }

  bytes(offset: number, size: number): Uint8Array {
    if (size <= 0 || !this.has(offset, size)) return new Uint8Array(0);
    return this.buffer.subarray(offset, offset + size);
  }

  /** ASCII/UTF-8 名字，遇到 NUL 截断；非法字节替换为 '.'。 */
  cstring(offset: number, max = 512): string {
    if (!this.has(offset)) return "";
    const end = Math.min(this.buffer.length, offset + max);
    let out = "";
    for (let i = offset; i < end; i += 1) {
      const byte = this.buffer[i] ?? 0;
      if (byte === 0) break;
      out += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
    }
    return out;
  }

  ascii(offset: number, size: number): string {
    const slice = this.bytes(offset, size);
    let out = "";
    for (const byte of slice) out += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
    return out;
  }

  latin1(offset: number, size: number): string {
    return Buffer.from(this.bytes(offset, size)).toString("latin1");
  }
}

export const alignUp = (value: number, alignment: number): number =>
  alignment <= 0 ? value : Math.ceil(value / alignment) * alignment;

export const alignDown = (value: number, alignment: number): number =>
  alignment <= 0 ? value : Math.floor(value / alignment) * alignment;

export const toHex = (value: number, width = 8): string =>
  `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;

export const hexBytes = (bytes: Uint8Array, separator = " "): string =>
  Array.from(bytes, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(separator);

export const sha256Bytes = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

export const sha256File = (path: string): string => {
  const bytes = readFileSync(path);
  return createHash("sha256").update(bytes).digest("hex");
};

export interface LoadedFile {
  readonly path: string;
  readonly size: number;
  readonly sha256: string;
  readonly bytes: Uint8Array;
}

export const loadFile = (path: string): LoadedFile => {
  const bytes = readFileSync(path);
  const stat = statSync(path);
  return {
    path,
    size: stat.size,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
  };
};

/** Shannon 熵（0..8）。空输入返回 0。 */
export const shannonEntropy = (bytes: Uint8Array): number => {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte] = (counts[byte] ?? 0) + 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
};

export const isPrintableRatio = (bytes: Uint8Array): number => {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const byte of bytes) {
    if ((byte >= 0x20 && byte < 0x7f) || byte === 0x09 || byte === 0x0a || byte === 0x0d) printable += 1;
  }
  return Number((printable / bytes.length).toFixed(4));
};

/** 在一段缓冲里搜索字节串，返回所有命中偏移。 */
export const indexOfAll = (
  haystack: Uint8Array,
  needle: Uint8Array,
  options: { start?: number; end?: number; limit?: number } = {},
): number[] => {
  const hits: number[] = [];
  if (needle.length === 0 || haystack.length < needle.length) return hits;
  const start = Math.max(0, options.start ?? 0);
  const end = Math.min(haystack.length, options.end ?? haystack.length);
  const limit = options.limit ?? 4096;
  const first = needle[0] ?? 0;
  for (let i = start; i <= end - needle.length; i += 1) {
    if (haystack[i] !== first) continue;
    let matched = true;
    for (let j = 1; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      hits.push(i);
      if (hits.length >= limit) break;
    }
  }
  return hits;
};

/** 'MZ' 之类的文本签名转字节串。 */
export const asciiBytes = (text: string): Uint8Array => Uint8Array.from(Buffer.from(text, "latin1"));

export const clamp = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));
