#!/usr/bin/env node
/**
 * 生成确定性测试样本：
 *   fixtures/packed-sample.exe   —— 合成 PE32 加壳样本（UPX 风格：UPX0 空洞 + pushad stub + push imm32;ret）
 *   fixtures/memory-dump.bin     —— 同一镜像的「内存 dump」布局（区段按 RVA 排布、raw 指针归零）
 * 样本只用于验证分析逻辑，不含真实恶意代码。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "fixtures");
mkdirSync(outDir, { recursive: true });

const IMAGE_BASE = 0x400000;
const FILE_ALIGN = 0x200;
const SECT_ALIGN = 0x1000;
const SIZE_OF_IMAGE = 0x6000;
const SIZE_OF_HEADERS = 0x400;
const ENTRY_RVA = 0x4000;

const sections = [
  { name: ".text", va: 0x1000, vsize: 0x1000, rawSize: 0x600, chars: 0x60000020 },
  { name: "UPX0", va: 0x2000, vsize: 0x2000, rawSize: 0x0, chars: 0xc0000080 },
  { name: "UPX1", va: 0x4000, vsize: 0x1000, rawSize: 0x400, chars: 0xe0000020 },
  { name: ".idata", va: 0x5000, vsize: 0x1000, rawSize: 0x600, chars: 0xc0000040 },
];

let cursor = SIZE_OF_HEADERS;
for (const section of sections) {
  if (section.rawSize === 0) {
    section.pointer = 0;
    continue;
  }
  section.pointer = cursor;
  cursor += section.rawSize;
}
const overlayOffset = cursor;

const mulberry32 = (seed) => {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) & 0xff;
  };
};

const totalSize = overlayOffset + 16;
const file = Buffer.alloc(totalSize);

// ---- DOS header + stub ----
file.write("MZ", 0, "latin1");
file.writeUInt16LE(0x90, 0x02);
file.writeUInt32LE(0x40, 0x3c);
file.write("This program cannot be run in DOS mode.\r\r\n$", 0x4e, "latin1");

// ---- PE signature + file header ----
file.writeUInt32LE(0x00004550, 0x40);
const FILE_HEADER = 0x44;
file.writeUInt16LE(0x014c, FILE_HEADER + 0); // i386
file.writeUInt16LE(sections.length, FILE_HEADER + 2);
file.writeUInt32LE(0x5f5e1000, FILE_HEADER + 4); // 固定时间戳
file.writeUInt32LE(0, FILE_HEADER + 8);
file.writeUInt32LE(0, FILE_HEADER + 12);
file.writeUInt16LE(0x00e0, FILE_HEADER + 16); // optional header size
file.writeUInt16LE(0x0102, FILE_HEADER + 18); // executable | 32bit

// ---- Optional header (PE32, 16 data dirs) ----
const opt = 0x58;
file.writeUInt16LE(0x010b, opt + 0);
file.writeUInt8(9, opt + 2);
file.writeUInt8(0, opt + 3);
file.writeUInt32LE(0x600, opt + 4); // SizeOfCode
file.writeUInt32LE(0x600, opt + 8); // SizeOfInitializedData
file.writeUInt32LE(0x2000, opt + 12); // SizeOfUninitializedData
file.writeUInt32LE(ENTRY_RVA, opt + 16);
file.writeUInt32LE(0x1000, opt + 20); // BaseOfCode
file.writeUInt32LE(0x5000, opt + 24); // BaseOfData
file.writeUInt32LE(IMAGE_BASE, opt + 28);
file.writeUInt32LE(SECT_ALIGN, opt + 32);
file.writeUInt32LE(FILE_ALIGN, opt + 36);
file.writeUInt16LE(6, opt + 40);
file.writeUInt16LE(0, opt + 42);
file.writeUInt16LE(0, opt + 44);
file.writeUInt16LE(0, opt + 46);
file.writeUInt16LE(6, opt + 48);
file.writeUInt16LE(0, opt + 50);
file.writeUInt32LE(0, opt + 52);
file.writeUInt32LE(SIZE_OF_IMAGE, opt + 56);
file.writeUInt32LE(SIZE_OF_HEADERS, opt + 60);
file.writeUInt32LE(0, opt + 64); // CheckSum（留 0：解析器把 0 视为未设置）
file.writeUInt16LE(3, opt + 68); // windows-cui
file.writeUInt16LE(0x8140, opt + 70); // DEP + NXCOMPAT + TS aware
file.writeUInt32LE(0x100000, opt + 72);
file.writeUInt32LE(0x1000, opt + 76);
file.writeUInt32LE(0x100000, opt + 80);
file.writeUInt32LE(0x1000, opt + 84);
file.writeUInt32LE(0, opt + 88);
file.writeUInt32LE(16, opt + 92);
const dataDir = opt + 96;
const setDirectory = (index, rva, size) => {
  file.writeUInt32LE(rva, dataDir + index * 8);
  file.writeUInt32LE(size, dataDir + index * 8 + 4);
};
setDirectory(1, 0x5000, 0x28); // import
setDirectory(9, 0x5150, 0x18); // tls
setDirectory(12, 0x5200, 0x0c); // IAT

// ---- Section table ----
const sectionTable = opt + 0x00e0;
sections.forEach((section, index) => {
  const base = sectionTable + index * 40;
  file.write(section.name.padEnd(8, "\0"), base, "latin1");
  file.writeUInt32LE(section.vsize, base + 8);
  file.writeUInt32LE(section.va, base + 12);
  file.writeUInt32LE(section.rawSize, base + 16);
  file.writeUInt32LE(section.pointer, base + 20);
  file.writeUInt32LE(0, base + 24);
  file.writeUInt32LE(0, base + 28);
  file.writeUInt16LE(0, base + 32);
  file.writeUInt16LE(0, base + 34);
  file.writeUInt32LE(section.chars, base + 36);
});

const sectionByName = (name) => sections.find((section) => section.name === name);
const rvaToOffset = (rva) => {
  for (const section of sections) {
    const span = Math.max(section.vsize, section.rawSize);
    if (rva >= section.va && rva < section.va + span) {
      const delta = rva - section.va;
      if (delta >= section.rawSize) return null;
      return section.pointer + delta;
    }
  }
  if (rva < SIZE_OF_HEADERS) return rva;
  return null;
};

// ---- .text：解压后的真实代码 ----
const text = sectionByName(".text");
const textCode = [0x55, 0x8b, 0xec, 0x33, 0xc0, 0x5d, 0xc3];
textCode.forEach((byte, index) => {
  file[text.pointer + index] = byte;
});

// ---- .UPX1：入口 stub ----
const upx1 = sectionByName("UPX1");
const stub = [
  0x60, // pushad
  0xbe, 0x00, 0x10, 0x40, 0x00, // mov esi, 0x401000
  0x8d, 0xbe, 0x00, 0xf0, 0xff, 0xff, // lea edi, [esi-0x1000]
  0x57, // push edi
  0x90, 0x90, 0x90, // nop × 3
  0xcd, 0x2d, // int 2d（反调试）
  0xf1, // icebp（反调试）
  0xff, 0x15, 0x00, 0x52, 0x40, 0x00, // call dword ptr [0x405200] → IAT: IsDebuggerPresent
  0x68, 0x00, 0x10, 0x40, 0x00, // push 0x401000  ← OEP VA
  0xc3, // ret
];
stub.forEach((byte, index) => {
  file[upx1.pointer + index] = byte;
});
// stub 之后填高熵数据（模拟压缩载荷）
const random = mulberry32(0xc0ffee);
for (let offset = stub.length; offset < upx1.rawSize; offset += 1) {
  file[upx1.pointer + offset] = random();
}
file.write("UPX!", upx1.pointer + upx1.rawSize - 8, "latin1");
file.writeUInt8(0x04, upx1.pointer + upx1.rawSize - 4);
file.writeUInt8(0x1a, upx1.pointer + upx1.rawSize - 3);

// ---- .idata：导入表 + TLS + 残留描述符 ----
const idata = sectionByName(".idata");
const writeAt = (rva, bytes) => {
  const offset = rvaToOffset(rva);
  if (offset === null) throw new Error(`rva 0x${rva.toString(16)} 不可写`);
  Buffer.from(bytes).copy(file, offset);
};
const u32 = (rva, value) => {
  const offset = rvaToOffset(rva);
  if (offset === null) throw new Error(`rva 0x${rva.toString(16)} 不可写`);
  file.writeUInt32LE(value >>> 0, offset);
};

// 描述符（KERNEL32）
u32(0x5000, 0x5300); // OriginalFirstThunk
u32(0x5004, 0);
u32(0x5008, 0);
u32(0x500c, 0x5100); // Name
u32(0x5010, 0x5200); // FirstThunk
writeAt(0x5100, Buffer.from("KERNEL32.dll\0", "latin1"));

// TLS 目录 + 回调数组
u32(0x5150, 0);
u32(0x5154, 0);
u32(0x5158, 0);
u32(0x515c, IMAGE_BASE + 0x5160); // AddressOfCallBacks
u32(0x5160, IMAGE_BASE + 0x1000); // callback #1 → .text
u32(0x5164, 0);

// IAT / ILT
const functions = [
  { name: "IsDebuggerPresent", nameRva: 0x5400, thunkRva: 0x5200 },
  { name: "VirtualProtect", nameRva: 0x5440, thunkRva: 0x5204 },
  { name: "GetTickCount", nameRva: 0x5480, thunkRva: 0x5208 },
];
functions.forEach((fn) => {
  u32(fn.thunkRva, fn.nameRva); // IAT
});
u32(0x5300, 0x5400);
u32(0x5304, 0x5440);
u32(0x5308, 0x5480);
u32(0x530c, 0);
[0x5400, 0x5440, 0x5480].forEach((rva, index) => {
  const offset = rvaToOffset(rva);
  const nameBytes = Buffer.from(functions[index].name + "\0", "latin1");
  file.writeUInt16LE(0, offset); // hint
  nameBytes.copy(file, offset + 2);
  void index;
});

// 残留的原始导入描述符（模拟壳没擦干净的旧表）
writeAt(0x54c0, Buffer.from("USER32.dll\0", "latin1"));
writeAt(0x54e0, Buffer.from("GDI32.dll\0", "latin1"));
u32(0x5500, 0x5300);
u32(0x5504, 0);
u32(0x5508, 0);
u32(0x550c, 0x54c0);
u32(0x5510, 0x5200);
u32(0x5514, 0x5300);
u32(0x5518, 0);
u32(0x551c, 0);
u32(0x5520, 0x54e0);
u32(0x5524, 0x5200);
for (let offset = 0x5528; offset < 0x553c; offset += 4) u32(offset, 0);

// ---- overlay ----
file.write("UPX!", overlayOffset, "latin1");
file.writeUInt8(0x04, overlayOffset + 4);
file.writeUInt8(0x1a, overlayOffset + 5);
file.writeUInt8(0x1f, overlayOffset + 6);
file.writeUInt8(0x00, overlayOffset + 7);

const samplePath = join(outDir, "packed-sample.exe");
writeFileSync(samplePath, file);

// ---- 内存 dump 布局 ----
const dump = Buffer.alloc(SIZE_OF_IMAGE);
file.copy(dump, 0, 0, SIZE_OF_HEADERS);
for (const section of sections) {
  if (section.rawSize === 0) continue;
  file.copy(dump, section.va, section.pointer, section.pointer + section.rawSize);
  // 典型 dump：区段头里的 raw 指针被清掉
  const index = sections.indexOf(section);
  const base = sectionTable + index * 40;
  dump.writeUInt32LE(0, base + 20);
}
const dumpPath = join(outDir, "memory-dump.bin");
writeFileSync(dumpPath, dump);

process.stdout.write(`sample: ${samplePath} (${file.length} bytes)\n`);
process.stdout.write(`dump:   ${dumpPath} (${dump.length} bytes)\n`);
