/**
 * PE32/PE32+ 静态解析器（加固版：全部循环有上限，畸形输入返回部分事实）。
 *
 * 设计约束：
 *  - 只读字节，不执行、不加载、不落盘。
 *  - 所有循环都有上限，畸形/截断输入返回已确认事实 + 显式局限，不抛未捕获异常。
 *  - RVA → 文件偏移一律走区段表；映射失败返回 null，绝不做"就近猜测"。
 */
import {
  ByteReader,
  alignUp,
  clamp,
  hexBytes,
  indexOfAll,
  sha256Bytes,
  shannonEntropy,
  toHex,
} from "../util/bytes.js";

export const DATA_DIRECTORY_NAMES = [
  "export",
  "import",
  "resource",
  "exception",
  "certificate",
  "basereloc",
  "debug",
  "architecture",
  "globalptr",
  "tls",
  "loadconfig",
  "bound-import",
  "iat",
  "delay-import",
  "clr-runtime",
  "reserved",
] as const;

export type DataDirectoryName = (typeof DATA_DIRECTORY_NAMES)[number];

export const MACHINE_NAMES: Readonly<Record<number, string>> = {
  0x014c: "i386",
  0x0166: "mips-r4000",
  0x0169: "mips-wce-v4",
  0x0184: "alpha",
  0x01a2: "sh3",
  0x01a6: "sh4",
  0x01c0: "arm",
  0x01c2: "thumb",
  0x01c4: "armv7",
  0x01d3: "am33",
  0x01f0: "powerpc",
  0x01f1: "powerpc-fp",
  0x0200: "ia64",
  0x0266: "mips16",
  0x0284: "alpha64",
  0x0366: "mips-fpu",
  0x0466: "mips16-fpu",
  0x0520: "mips-wce-v2",
  0x0ebc: "efi-bytecode",
  0x5032: "riscv32",
  0x5064: "riscv64",
  0x5128: "riscv128",
  0x6232: "loongarch32",
  0x6264: "loongarch64",
  0x8664: "x64",
  0x9041: "m32r",
  0xaa64: "arm64",
  0xa641: "arm64ec",
  0xc0ee: "cuda",
};

export const SUBSYSTEM_NAMES: Readonly<Record<number, string>> = {
  0: "unknown",
  1: "native",
  2: "windows-gui",
  3: "windows-cui",
  5: "os2-cui",
  7: "posix-cui",
  8: "native-windows",
  9: "windows-ce",
  10: "efi-application",
  11: "efi-boot-service",
  12: "efi-runtime",
  13: "efi-rom",
  14: "xbox",
  16: "windows-boot",
};

export interface SectionFlags {
  readonly code: boolean;
  readonly initializedData: boolean;
  readonly uninitializedData: boolean;
  readonly executable: boolean;
  readonly readable: boolean;
  readonly writable: boolean;
  readonly shared: boolean;
  readonly discardable: boolean;
}

export interface PeSection {
  readonly index: number;
  readonly name: string;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly sizeOfRawData: number;
  readonly pointerToRawData: number;
  readonly characteristics: number;
  readonly entropy: number;
  readonly printableRatio: number;
  readonly flags: SectionFlags;
  /** 文件内真实可读长度（截断文件会小于 sizeOfRawData）。 */
  readonly availableRawBytes: number;
  readonly truncated: boolean;
}

export interface PeImportFunction {
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly hint: number | null;
  readonly thunkRva: number;
  readonly iatRva: number;
  readonly iatVa: number;
}

export interface PeImportModule {
  readonly name: string;
  readonly descriptorRva: number;
  readonly originalFirstThunkRva: number;
  readonly firstThunkRva: number;
  readonly timestamp: number;
  readonly forwarderChain: number;
  readonly viaOrdinalOnly: boolean;
  readonly functions: readonly PeImportFunction[];
  readonly truncated: boolean;
}

export interface PeExport {
  readonly name: string | null;
  readonly ordinal: number;
  readonly rva: number;
  readonly va: number;
  readonly forwarder: string | null;
}

export interface PeTlsInfo {
  readonly directoryRva: number;
  readonly directorySize: number;
  readonly callbacksVa: number;
  readonly callbackRvas: readonly number[];
  readonly callbackVas: readonly number[];
  readonly hasCallbacks: boolean;
}

export interface PeDebugEntry {
  readonly type: number;
  readonly typeName: string;
  readonly sizeOfData: number;
  readonly pointerToRawData: number;
  readonly pdbPath: string | null;
  readonly guid: string | null;
  readonly age: number | null;
}

export interface PeResourceType {
  readonly id: number | null;
  readonly name: string | null;
  readonly declaredName: string;
  readonly languageCount: number;
  readonly payloadRvas: readonly number[];
}

export interface PeOverlay {
  readonly offset: number;
  readonly size: number;
  readonly entropy: number;
  readonly sha256: string;
  readonly markers: readonly string[];
}

export interface PeRichEntry {
  readonly productId: number;
  readonly buildId: number;
  readonly count: number;
  readonly tool: string;
}

export interface PeAnomaly {
  readonly id: string;
  readonly severity: "info" | "low" | "medium" | "high";
  readonly detail: string;
  readonly rva?: number;
}

export interface PeDataDirectory {
  readonly index: number;
  readonly name: DataDirectoryName;
  readonly rva: number;
  readonly size: number;
  readonly fileOffset: number | null;
}

export interface PeImage {
  readonly source: { readonly path: string | null; readonly size: number; readonly sha256: string };
  readonly dosMagic: number;
  readonly peOffset: number;
  /** 区段表在文件中的起始偏移（PE 签名 + 文件头 + 可选头）。 */
  readonly sectionTableOffset: number;
  /** IMAGE_OPTIONAL_HEADER 在文件中的起始偏移。 */
  readonly optionalHeaderOffset: number;
  readonly machine: number;
  readonly machineName: string;
  readonly is64: boolean;
  readonly numberOfSections: number;
  readonly timeDateStamp: number;
  readonly characteristics: number;
  readonly optionalMagic: number;
  readonly linkerVersion: { readonly major: number; readonly minor: number };
  readonly osVersion: { readonly major: number; readonly minor: number };
  readonly imageVersion: { readonly major: number; readonly minor: number };
  readonly subsystemVersion: { readonly major: number; readonly minor: number };
  readonly entryPointRva: number;
  readonly entryPointVa: number;
  readonly imageBase: number;
  readonly sectionAlignment: number;
  readonly fileAlignment: number;
  readonly sizeOfImage: number;
  readonly sizeOfHeaders: number;
  readonly sizeOfCode: number;
  readonly sizeOfInitializedData: number;
  readonly checksum: number;
  readonly computedChecksum: number;
  readonly checksumValid: boolean;
  readonly subsystem: number;
  readonly subsystemName: string;
  readonly dllCharacteristics: number;
  readonly dll: boolean;
  readonly sections: readonly PeSection[];
  readonly dataDirectories: readonly PeDataDirectory[];
  readonly imports: readonly PeImportModule[];
  readonly delayImports: readonly PeImportModule[];
  readonly exports: readonly PeExport[];
  readonly tls: PeTlsInfo | null;
  readonly debug: readonly PeDebugEntry[];
  readonly resources: readonly PeResourceType[];
  readonly richHeader: { readonly key: number; readonly entries: readonly PeRichEntry[] } | null;
  readonly overlay: PeOverlay | null;
  readonly clrRuntime: {
    readonly headerRva: number;
    readonly metaDataRva: number;
    readonly metaDataSize: number;
    readonly flags: number;
    readonly entryPointToken: number;
    readonly nativeHeaderRva: number;
  } | null;
  readonly anomalies: readonly PeAnomaly[];
  readonly coverage: readonly string[];
  readonly binaryReader: ByteReader;
}

export interface PeParseLimits {
  readonly maxSections?: number;
  readonly maxImportModules?: number;
  readonly maxImportsPerModule?: number;
  readonly maxExports?: number;
  readonly maxTlsCallbacks?: number;
  readonly maxResources?: number;
  readonly maxDebugEntries?: number;
}

const SECTION_FLAG_BITS = {
  code: 0x00000020,
  initializedData: 0x00000040,
  uninitializedData: 0x00000080,
  shared: 0x10000000,
  executable: 0x20000000,
  readable: 0x40000000,
  writable: 0x80000000,
  discardable: 0x02000000,
} as const;

const DEBUG_TYPE_NAMES: Readonly<Record<number, string>> = {
  0: "unknown",
  1: "coff",
  2: "codeview",
  3: "fpo",
  4: "misc",
  5: "exception",
  6: "fixup",
  7: "omap-to-src",
  8: "omap-from-src",
  9: "borland",
  10: "reserved10",
  11: "clsid",
  12: "vc-feature",
  13: "pogo",
  14: "iltcg",
  16: "repro",
  17: "exdig",
  20: "embedded-portable-pdb",
};

const RESOURCE_TYPE_NAMES: Readonly<Record<number, string>> = {
  1: "cursor",
  2: "bitmap",
  3: "icon",
  4: "menu",
  5: "dialog",
  6: "string-table",
  7: "font-directory",
  8: "font",
  9: "accelerator",
  10: "rcdata",
  11: "message-table",
  12: "group-cursor",
  14: "group-icon",
  16: "version",
  17: "dlginclude",
  19: "plugplay",
  20: "vxd",
  21: "anicursor",
  22: "aniicon",
  23: "html",
  24: "manifest",
  240: "dlginit",
  241: "typelib",
};

const OVERLAY_MARKERS: readonly string[] = [
  "UPX!",
  "MEI\x0c\x0b\x0a\x0b\x0e",
  "pyi-",
  "PyInstaller",
  "python3",
  "asar",
  "Inno Setup Setup Data",
  "NullsoftInst",
  "Nullsoft",
  "7z\xbc\xaf\x27\x1c",
  "PK\x03\x04",
  "MSCF",
  "MPRESS",
  "Armadillo",
  "Themida",
  "VMProtect",
  "Enigma protector",
  "PEC2",
  "PECompact2",
  "SFXCA",
];

const readU32At = (reader: ByteReader, offset: number): number => reader.u32(offset);

export interface ParsePeOptions extends PeParseLimits {
  readonly path?: string | null;
}

export const isPeBytes = (bytes: Uint8Array): boolean => {
  const reader = new ByteReader(bytes);
  if (reader.u16(0) !== 0x5a4d) return false;
  const peOffset = reader.u32(0x3c);
  if (!reader.has(peOffset, 4)) return false;
  return reader.u32(peOffset) === 0x00004550;
};

export const computePeChecksum = (bytes: Uint8Array, checksumOffset: number): number => {
  // IMAGE_OPTIONAL_HEADER.CheckSum 在计算时按 0 处理；这里直接跳过该字段。
  let sum = 0;
  const length = bytes.length;
  const end = length - (length % 2);
  for (let offset = 0; offset < end; offset += 2) {
    if (offset === checksumOffset || offset === checksumOffset + 2) continue;
    const word = ((bytes[offset] ?? 0) | ((bytes[offset + 1] ?? 0) << 8)) >>> 0;
    sum = (sum + word) >>> 0;
    sum = ((sum & 0xffff) + (sum >>> 16)) >>> 0;
  }
  if (length % 2 === 1) {
    sum = (sum + (bytes[length - 1] ?? 0)) >>> 0;
    sum = ((sum & 0xffff) + (sum >>> 16)) >>> 0;
  }
  sum = ((sum & 0xffff) + (sum >>> 16)) >>> 0;
  return (sum + length) >>> 0;
};

export const parsePe = (bytes: Uint8Array, options: ParsePeOptions = {}): PeImage => {
  const reader = new ByteReader(bytes);
  const limits = {
    maxSections: options.maxSections ?? 96,
    maxImportModules: options.maxImportModules ?? 2048,
    maxImportsPerModule: options.maxImportsPerModule ?? 8192,
    maxExports: options.maxExports ?? 100_000,
    maxTlsCallbacks: options.maxTlsCallbacks ?? 256,
    maxResources: options.maxResources ?? 4096,
    maxDebugEntries: options.maxDebugEntries ?? 256,
  };

  if (bytes.length === 0) throw new Error("empty input");
  if (reader.u16(0) !== 0x5a4d) throw new Error("missing MZ header");
  const peOffset = reader.u32(0x3c);
  if (!reader.has(peOffset, 24) || reader.u32(peOffset) !== 0x00004550) {
    throw new Error("missing PE signature");
  }

  const fileHeaderOffset = peOffset + 4;
  const machine = reader.u16(fileHeaderOffset);
  const numberOfSections = reader.u16(fileHeaderOffset + 2);
  const timeDateStamp = reader.u32(fileHeaderOffset + 4);
  const sizeOfOptionalHeader = reader.u16(fileHeaderOffset + 16);
  const characteristics = reader.u16(fileHeaderOffset + 18);

  const optionalOffset = fileHeaderOffset + 20;
  const optionalMagic = reader.u16(optionalOffset);
  const is64 = optionalMagic === 0x20b;
  if (!is64 && optionalMagic !== 0x10b) {
    throw new Error(`unsupported optional header magic ${toHex(optionalMagic, 4)}`);
  }

  const field = (offset32: number, offset64: number): number =>
    reader.u32(optionalOffset + (is64 ? offset64 : offset32));

  const ptrField = (offset32: number, offset64: number): number =>
    reader.ptr(optionalOffset + (is64 ? offset64 : offset32), is64);

  const entryPointRva = field(16, 16);
  const imageBase = ptrField(28, 24);
  const sectionAlignment = field(32, 32);
  const fileAlignment = field(36, 36);
  const sizeOfImage = field(56, 56);
  const sizeOfHeaders = field(60, 60);
  const sizeOfCode = field(4, 4);
  const sizeOfInitializedData = field(8, 8);
  const checksum = field(64, 64);
  const subsystem = reader.u16(optionalOffset + 68);
  const dllCharacteristics = reader.u16(optionalOffset + 70);
  const numberOfRvaAndSizes = field(92, 108);
  const dataDirectoryOffset = optionalOffset + (is64 ? 112 : 96);

  const linkerVersion = {
    major: reader.u8(optionalOffset + 2),
    minor: reader.u8(optionalOffset + 3),
  };
  const osVersion = { major: reader.u8(optionalOffset + 40), minor: reader.u8(optionalOffset + 42) };
  const imageVersion = { major: reader.u8(optionalOffset + 44), minor: reader.u8(optionalOffset + 46) };
  const subsystemVersion = {
    major: reader.u8(optionalOffset + 48),
    minor: reader.u8(optionalOffset + 50),
  };

  const coverage: string[] = [];
  const anomalies: PeAnomaly[] = [];

  // ---- 区段表 ----
  const sections: PeSection[] = [];
  const sectionTableOffset = optionalOffset + sizeOfOptionalHeader;
  const sectionCount = Math.min(numberOfSections, limits.maxSections);
  for (let index = 0; index < sectionCount; index += 1) {
    const base = sectionTableOffset + index * 40;
    if (!reader.has(base, 40)) {
      anomalies.push({
        id: "section-table-truncated",
        severity: "high",
        detail: `区段表在第 ${index} 项处被截断（声明 ${numberOfSections} 项）`,
      });
      break;
    }
    const name = reader.cstring(base, 8).trim();
    const virtualSize = readU32At(reader, base + 8);
    const virtualAddress = readU32At(reader, base + 12);
    const sizeOfRawData = readU32At(reader, base + 16);
    const pointerToRawData = readU32At(reader, base + 20);
    const sectionCharacteristics = readU32At(reader, base + 36);
    const availableRawBytes = clamp(bytes.length - pointerToRawData, 0, sizeOfRawData);
    const raw = reader.bytes(pointerToRawData, availableRawBytes);
    sections.push({
      index,
      name,
      virtualAddress,
      virtualSize,
      sizeOfRawData,
      pointerToRawData,
      characteristics: sectionCharacteristics,
      entropy: shannonEntropy(raw),
      printableRatio: Number(
        (Array.from(raw).filter((byte) => byte >= 0x20 && byte < 0x7f).length / Math.max(1, raw.length)).toFixed(4),
      ),
      flags: {
        code: (sectionCharacteristics & SECTION_FLAG_BITS.code) !== 0,
        initializedData: (sectionCharacteristics & SECTION_FLAG_BITS.initializedData) !== 0,
        uninitializedData: (sectionCharacteristics & SECTION_FLAG_BITS.uninitializedData) !== 0,
        executable: (sectionCharacteristics & SECTION_FLAG_BITS.executable) !== 0,
        readable: (sectionCharacteristics & SECTION_FLAG_BITS.readable) !== 0,
        writable: (sectionCharacteristics & SECTION_FLAG_BITS.writable) !== 0,
        shared: (sectionCharacteristics & SECTION_FLAG_BITS.shared) !== 0,
        discardable: (sectionCharacteristics & SECTION_FLAG_BITS.discardable) !== 0,
      },
      availableRawBytes,
      truncated: availableRawBytes < sizeOfRawData,
    });
  }
  coverage.push(`sections:${sections.length}/${numberOfSections}`);

  const sectionByVa = [...sections].sort((a, b) => a.virtualAddress - b.virtualAddress);
  const maxSectionEnd = sections.reduce(
    (max, section) => Math.max(max, section.pointerToRawData + section.sizeOfRawData),
    0,
  );

  const sectionForRva = (rva: number): PeSection | null => {
    for (const section of sectionByVa) {
      const span = Math.max(section.virtualSize, section.sizeOfRawData);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) return section;
    }
    return null;
  };

  /** RVA → 文件偏移。头部区域按 1:1 映射；其余必须落在区段 raw 数据内。 */
  const rvaToOffset = (rva: number): number | null => {
    if (!Number.isFinite(rva) || rva < 0) return null;
    if (rva < Math.min(sizeOfHeaders, bytes.length)) return rva;
    const section = sectionForRva(rva);
    if (!section) return null;
    const delta = rva - section.virtualAddress;
    if (delta >= section.availableRawBytes) return null;
    return section.pointerToRawData + delta;
  };

  const offsetToRva = (offset: number): number | null => {
    for (const section of sections) {
      if (offset >= section.pointerToRawData && offset < section.pointerToRawData + section.availableRawBytes) {
        return section.virtualAddress + (offset - section.pointerToRawData);
      }
    }
    if (offset < Math.min(sizeOfHeaders, bytes.length)) return offset;
    return null;
  };

  const readRvaCString = (rva: number, max = 256): string | null => {
    const offset = rvaToOffset(rva);
    if (offset === null) return null;
    const text = reader.cstring(offset, max);
    return text.length > 0 ? text : null;
  };

  // ---- 数据目录 ----
  const dataDirectories: PeDataDirectory[] = [];
  const directoryCount = Math.min(numberOfRvaAndSizes, DATA_DIRECTORY_NAMES.length, 16);
  for (let index = 0; index < directoryCount; index += 1) {
    const base = dataDirectoryOffset + index * 8;
    const rva = reader.u32(base);
    const size = reader.u32(base + 4);
    dataDirectories.push({
      index,
      name: DATA_DIRECTORY_NAMES[index] ?? "reserved",
      rva,
      size,
      fileOffset: rva === 0 ? null : rvaToOffset(rva),
    });
  }
  const directory = (name: DataDirectoryName): PeDataDirectory | null =>
    dataDirectories.find((entry) => entry.name === name && entry.rva !== 0) ?? null;
  coverage.push(`data-directories:${dataDirectories.length}`);

  // ---- 导入表 ----
  const parseThunkName = (thunkValue: number, isOrdinal: boolean): { name: string | null; ordinal: number | null; hint: number | null } => {
    if (isOrdinal) return { name: null, ordinal: thunkValue & 0xffff, hint: null };
    const nameRva = thunkValue;
    const offset = rvaToOffset(nameRva);
    if (offset === null) return { name: null, ordinal: null, hint: null };
    const hint = reader.u16(offset);
    const name = reader.cstring(offset + 2, 256);
    return { name: name.length > 0 ? name : null, ordinal: null, hint };
  };

  const parseImportTable = (tableRva: number, tableSize: number, maxModules: number): PeImportModule[] => {
    const modules: PeImportModule[] = [];
    const startOffset = rvaToOffset(tableRva);
    if (startOffset === null) return modules;
    const descriptorSize = 20;
    for (let index = 0; index < maxModules; index += 1) {
      const base = startOffset + index * descriptorSize;
      if (!reader.has(base, descriptorSize)) break;
      const iltRva = reader.u32(base);
      const timestamp = reader.u32(base + 4);
      const forwarderChain = reader.u32(base + 8);
      const nameRva = reader.u32(base + 12);
      const iatRva = reader.u32(base + 16);
      if (iltRva === 0 && nameRva === 0 && iatRva === 0) break;
      const moduleName = readRvaCString(nameRva, 256) ?? "";
      const ordinalOnly = !iltRva || iltRva === iatRva ? iltRva === 0 : false;
      const thunkRva = iltRva !== 0 ? iltRva : iatRva;
      const thunkOffset = rvaToOffset(thunkRva);
      const functions: PeImportFunction[] = [];
      let truncated = false;
      if (thunkOffset !== null) {
        const stride = is64 ? 8 : 4;
        for (let slot = 0; slot < limits.maxImportsPerModule; slot += 1) {
          const slotOffset = thunkOffset + slot * stride;
          if (!reader.has(slotOffset, stride)) {
            truncated = true;
            break;
          }
          const raw = reader.ptr(slotOffset, is64);
          if (raw === 0) break;
          const ordinalFlag = is64 ? 1n << 63n : 0x80000000;
          const isOrdinal = is64 ? BigInt(raw) >= ordinalFlag : (raw & 0x80000000) !== 0;
          const value = is64 ? raw : raw & 0x7fffffff;
          const parsed = parseThunkName(value, isOrdinal);
          functions.push({
            name: parsed.name,
            ordinal: parsed.ordinal,
            hint: parsed.hint,
            thunkRva: thunkRva + slot * stride,
            iatRva: iatRva + slot * stride,
            iatVa: imageBase + iatRva + slot * stride,
          });
        }
      }
      modules.push({
        name: moduleName,
        descriptorRva: tableRva + index * descriptorSize,
        originalFirstThunkRva: iltRva,
        firstThunkRva: iatRva,
        timestamp,
        forwarderChain,
        viaOrdinalOnly: ordinalOnly || functions.every((fn) => fn.name === null),
        functions,
        truncated,
      });
      void tableSize;
    }
    return modules;
  };

  const importDirectory = directory("import");
  const imports = importDirectory
    ? parseImportTable(importDirectory.rva, importDirectory.size, limits.maxImportModules)
    : [];
  coverage.push(`import-modules:${imports.length}`);

  const delayImportDirectory = directory("delay-import");
  const delayImports: PeImportModule[] = [];
  if (delayImportDirectory) {
    const startOffset = rvaToOffset(delayImportDirectory.rva);
    if (startOffset !== null) {
      for (let index = 0; index < Math.min(limits.maxImportModules, 512); index += 1) {
        const base = startOffset + index * 32;
        if (!reader.has(base, 32)) break;
        const attributes = reader.u32(base);
        const nameField = reader.u32(base + 4);
        const iatField = reader.u32(base + 12);
        const intField = reader.u32(base + 16);
        if (nameField === 0 && iatField === 0) break;
        const useRva = (attributes & 1) !== 0;
        const toRva = (value: number): number => (useRva ? value : value >= imageBase ? value - imageBase : 0);
        const nameRva = toRva(nameField);
        const iatRva = toRva(iatField);
        const intRva = toRva(intField);
        const moduleName = readRvaCString(nameRva, 256) ?? "";
        const thunkRva = intRva !== 0 ? intRva : iatRva;
        const thunkOffset = rvaToOffset(thunkRva);
        const functions: PeImportFunction[] = [];
        if (thunkOffset !== null) {
          const stride = is64 ? 8 : 4;
          for (let slot = 0; slot < limits.maxImportsPerModule; slot += 1) {
            const slotOffset = thunkOffset + slot * stride;
            if (!reader.has(slotOffset, stride)) break;
            const raw = reader.ptr(slotOffset, is64);
            if (raw === 0) break;
            const isOrdinal = is64 ? BigInt(raw) >= 1n << 63n : (raw & 0x80000000) !== 0;
            const value = is64 ? raw : raw & 0x7fffffff;
            const parsed = parseThunkName(value, isOrdinal);
            functions.push({
              name: parsed.name,
              ordinal: parsed.ordinal,
              hint: parsed.hint,
              thunkRva: thunkRva + slot * stride,
              iatRva: iatRva + slot * stride,
              iatVa: imageBase + iatRva + slot * stride,
            });
          }
        }
        delayImports.push({
          name: moduleName,
          descriptorRva: delayImportDirectory.rva + index * 32,
          originalFirstThunkRva: intRva,
          firstThunkRva: iatRva,
          timestamp: 0,
          forwarderChain: 0,
          viaOrdinalOnly: functions.every((fn) => fn.name === null),
          functions,
          truncated: false,
        });
      }
    }
  }
  coverage.push(`delay-import-modules:${delayImports.length}`);

  // ---- 导出表 ----
  const exports: PeExport[] = [];
  const exportDirectory = directory("export");
  if (exportDirectory) {
    const base = rvaToOffset(exportDirectory.rva);
    if (base !== null && reader.has(base, 40)) {
      const numberOfFunctions = reader.u32(base + 20);
      const numberOfNames = reader.u32(base + 24);
      const addressOfFunctions = reader.u32(base + 28);
      const addressOfNames = reader.u32(base + 32);
      const addressOfNameOrdinals = reader.u32(base + 36);
      const ordinalBase = reader.u32(base + 16);
      const functionsOffset = rvaToOffset(addressOfFunctions);
      const namesOffset = rvaToOffset(addressOfNames);
      const ordinalsOffset = rvaToOffset(addressOfNameOrdinals);
      const total = Math.min(numberOfFunctions, limits.maxExports);
      const nameByIndex = new Map<number, string>();
      if (namesOffset !== null && ordinalsOffset !== null) {
        for (let index = 0; index < Math.min(numberOfNames, limits.maxExports); index += 1) {
          const nameRva = reader.u32(namesOffset + index * 4);
          const name = readRvaCString(nameRva, 256);
          const ordinalIndex = reader.u16(ordinalsOffset + index * 2);
          if (name) nameByIndex.set(ordinalIndex, name);
        }
      }
      if (functionsOffset !== null) {
        for (let index = 0; index < total; index += 1) {
          const rva = reader.u32(functionsOffset + index * 4);
          if (rva === 0) continue;
          const inExportRange =
            rva >= exportDirectory.rva && rva < exportDirectory.rva + Math.max(exportDirectory.size, 1);
          const forwarder = inExportRange ? readRvaCString(rva, 256) : null;
          exports.push({
            name: nameByIndex.get(index) ?? null,
            ordinal: ordinalBase + index,
            rva,
            va: imageBase + rva,
            forwarder,
          });
        }
      }
    }
  }
  coverage.push(`exports:${exports.length}`);

  // ---- TLS ----
  let tls: PeTlsInfo | null = null;
  const tlsDirectory = directory("tls");
  if (tlsDirectory) {
    const base = rvaToOffset(tlsDirectory.rva);
    if (base !== null && reader.has(base, is64 ? 40 : 24)) {
      const callbacksFieldOffset = base + (is64 ? 24 : 12);
      const callbacksVa = reader.ptr(callbacksFieldOffset, is64);
      const callbacksRva = callbacksVa >= imageBase ? callbacksVa - imageBase : 0;
      const callbacksOffset = callbacksRva > 0 ? rvaToOffset(callbacksRva) : null;
      const callbackVas: number[] = [];
      const callbackRvas: number[] = [];
      if (callbacksOffset !== null) {
        for (let index = 0; index < limits.maxTlsCallbacks; index += 1) {
          const slot = callbacksOffset + index * (is64 ? 8 : 4);
          if (!reader.has(slot, is64 ? 8 : 4)) break;
          const va = reader.ptr(slot, is64);
          if (va === 0) break;
          callbackVas.push(va);
          callbackRvas.push(va >= imageBase ? va - imageBase : va);
        }
      }
      tls = {
        directoryRva: tlsDirectory.rva,
        directorySize: tlsDirectory.size,
        callbacksVa,
        callbackRvas,
        callbackVas,
        hasCallbacks: callbackVas.length > 0,
      };
    }
  }
  coverage.push(`tls-callbacks:${tls?.callbackRvas.length ?? 0}`);

  // ---- 调试目录 ----
  const debug: PeDebugEntry[] = [];
  const debugDirectory = directory("debug");
  if (debugDirectory) {
    const base = rvaToOffset(debugDirectory.rva);
    if (base !== null) {
      for (let index = 0; index < limits.maxDebugEntries; index += 1) {
        const entryBase = base + index * 28;
        if (!reader.has(entryBase, 28)) break;
        const type = reader.u32(entryBase + 12);
        const sizeOfData = reader.u32(entryBase + 16);
        const addressOfRawData = reader.u32(entryBase + 20);
        const pointerToRawData = reader.u32(entryBase + 24);
        let pdbPath: string | null = null;
        let guid: string | null = null;
        let age: number | null = null;
        const dataOffset = pointerToRawData !== 0 ? pointerToRawData : rvaToOffset(addressOfRawData) ?? null;
        if (type === 2 && dataOffset !== null && reader.has(dataOffset, 24)) {
          const signature = reader.ascii(dataOffset, 4);
          if (signature === "RSDS") {
            const raw = reader.bytes(dataOffset + 4, 16);
            guid = hexBytes(raw, "").toLowerCase();
            age = reader.u32(dataOffset + 20);
            pdbPath = reader.cstring(dataOffset + 24, 260) || null;
          } else if (signature === "NB10") {
            age = reader.u32(dataOffset + 8);
            pdbPath = reader.cstring(dataOffset + 16, 260) || null;
          }
        }
        debug.push({
          type,
          typeName: DEBUG_TYPE_NAMES[type] ?? `type-${type}`,
          sizeOfData,
          pointerToRawData,
          pdbPath,
          guid,
          age,
        });
      }
    }
  }
  coverage.push(`debug-entries:${debug.length}`);

  // ---- 资源目录（三层：类型/名称/语言）----
  const resources: PeResourceType[] = [];
  const resourceDirectory = directory("resource");
  if (resourceDirectory) {
    const rootOffset = rvaToOffset(resourceDirectory.rva);
    if (rootOffset !== null) {
      const readDirEntries = (dirOffset: number, budget: { left: number }) => {
        const entries: { name: string | null; id: number | null; isDirectory: boolean; target: number }[] = [];
        const count = Math.min(reader.u16(dirOffset + 12), 256);
        for (let index = 0; index < count && budget.left > 0; index += 1) {
          const entryBase = dirOffset + 16 + index * 8;
          if (!reader.has(entryBase, 8)) break;
          const nameField = reader.u32(entryBase);
          const targetField = reader.u32(entryBase + 4);
          budget.left -= 1;
          let name: string | null = null;
          let id: number | null = null;
          if ((nameField & 0x80000000) !== 0) {
            const stringOffset = rootOffset + (nameField & 0x7fffffff);
            if (reader.has(stringOffset, 2)) {
              const length = reader.u16(stringOffset);
              name = Buffer.from(reader.bytes(stringOffset + 2, Math.min(length, 128) * 2)).toString("utf16le");
            }
          } else {
            id = nameField;
          }
          entries.push({ name, id, isDirectory: (targetField & 0x80000000) !== 0, target: targetField & 0x7fffffff });
        }
        return entries;
      };

      const budget = { left: limits.maxResources };
      const typeEntries = readDirEntries(rootOffset, budget);
      for (const typeEntry of typeEntries) {
        if (!typeEntry.isDirectory) continue;
        const typeDirOffset = rootOffset + typeEntry.target;
        const nameEntries = readDirEntries(typeDirOffset, budget);
        const payloadRvas: number[] = [];
        let languageCount = 0;
        for (const nameEntry of nameEntries) {
          if (!nameEntry.isDirectory) continue;
          const langDirOffset = rootOffset + nameEntry.target;
          const langEntries = readDirEntries(langDirOffset, budget);
          languageCount += langEntries.length;
          for (const langEntry of langEntries) {
            if (langEntry.isDirectory) continue;
            const dataEntryOffset = rootOffset + langEntry.target;
            if (!reader.has(dataEntryOffset, 16)) continue;
            payloadRvas.push(reader.u32(dataEntryOffset));
          }
        }
        const declaredId = typeEntry.id;
        const declaredName = typeEntry.name ?? (declaredId !== null ? String(declaredId) : "?");
        resources.push({
          id: declaredId,
          name: declaredId !== null ? RESOURCE_TYPE_NAMES[declaredId] ?? null : typeEntry.name,
          declaredName:
            declaredId !== null && RESOURCE_TYPE_NAMES[declaredId]
              ? `${RESOURCE_TYPE_NAMES[declaredId]}(${declaredId})`
              : declaredName,
          languageCount,
          payloadRvas,
        });
      }
    }
  }
  coverage.push(`resource-types:${resources.length}`);

  // ---- Rich header ----
  let richHeader: PeImage["richHeader"] = null;
  {
    const scanStart = Math.max(0, peOffset - 0x400);
    const richMatches = indexOfAll(bytes, Uint8Array.from([0x52, 0x69, 0x63, 0x68]), {
      start: scanStart,
      end: peOffset,
      limit: 4,
    });
    const richOffset = richMatches.length > 0 ? (richMatches[richMatches.length - 1] ?? -1) : -1;
    if (richOffset >= 0 && reader.has(richOffset + 8)) {
      const products: PeRichEntry[] = [];
      const key = reader.u32(richOffset + 4);
      let danS = -1;
      for (let cursor = richOffset - 4; cursor >= scanStart; cursor -= 4) {
        if ((reader.u32(cursor) ^ key) === 0x536e6144) {
          danS = cursor;
          break;
        }
      }
      if (danS >= 0) {
        for (let cursor = danS + 16; cursor + 8 <= richOffset; cursor += 8) {
          const value = reader.u32(cursor) ^ key;
          const count = reader.u32(cursor + 4) ^ key;
          const productId = value >>> 16;
          const buildId = value & 0xffff;
          products.push({
            productId,
            buildId,
            count,
            tool: `prod=0x${productId.toString(16)} build=${buildId}`,
          });
        }
      }
      richHeader = { key, entries: products };
    }
  }

  // ---- Overlay ----
  let overlay: PeOverlay | null = null;
  if (maxSectionEnd > 0 && bytes.length > maxSectionEnd) {
    const overlayBytes = reader.bytes(maxSectionEnd, bytes.length - maxSectionEnd);
    const markers: string[] = [];
    for (const marker of OVERLAY_MARKERS) {
      if (marker.includes("\x00")) continue;
      const needle = Uint8Array.from(Buffer.from(marker, "latin1"));
      if (indexOfAll(overlayBytes, needle, { limit: 1 }).length > 0) markers.push(marker);
    }
    for (const marker of OVERLAY_MARKERS) {
      if (!marker.includes("\x00")) continue;
      const needle = Uint8Array.from(Buffer.from(marker, "latin1"));
      if (indexOfAll(overlayBytes, needle, { limit: 1 }).length > 0) markers.push(marker.replace(/[^\x20-\x7e]/g, "?"));
    }
    overlay = {
      offset: maxSectionEnd,
      size: bytes.length - maxSectionEnd,
      entropy: shannonEntropy(overlayBytes),
      sha256: sha256Bytes(overlayBytes),
      markers,
    };
  }

  // ---- CLR ----
  let clrRuntime: PeImage["clrRuntime"] = null;
  const clrDirectory = directory("clr-runtime");
  if (clrDirectory) {
    const base = rvaToOffset(clrDirectory.rva);
    if (base !== null && reader.has(base, 72)) {
      clrRuntime = {
        headerRva: clrDirectory.rva,
        metaDataRva: reader.u32(base + 8),
        metaDataSize: reader.u32(base + 12),
        flags: reader.u32(base + 16),
        entryPointToken: reader.u32(base + 20),
        nativeHeaderRva: reader.u32(base + 48),
      };
    }
  }

  // ---- 结构异常 ----
  const entrySection = sectionForRva(entryPointRva);
  if (entryPointRva !== 0 && entrySection === null) {
    anomalies.push({
      id: "entry-outside-sections",
      severity: "high",
      detail: `入口点 ${toHex(entryPointRva)} 不在任何区段内（可能被抹掉或畸形）`,
      rva: entryPointRva,
    });
  }
  for (const section of sections) {
    if (section.sizeOfRawData === 0 && section.virtualSize > 0) {
      anomalies.push({
        id: "virtual-only-section",
        severity: "high",
        detail: `区段 ${section.name || `#${section.index}`} 无文件数据但有 VirtualSize ${section.virtualSize}（典型解压目标 / UPX0 形态）`,
        rva: section.virtualAddress,
      });
    }
    if (section.flags.executable && section.flags.writable) {
      anomalies.push({
        id: "rwx-section",
        severity: "high",
        detail: `区段 ${section.name || `#${section.index}`} 同时可写可执行（RWX）`,
        rva: section.virtualAddress,
      });
    }
    if (section.truncated) {
      anomalies.push({
        id: "truncated-section",
        severity: "medium",
        detail: `区段 ${section.name || `#${section.index}`} 声明 raw ${section.sizeOfRawData} 字节，文件内仅剩 ${section.availableRawBytes} 字节`,
        rva: section.virtualAddress,
      });
    }
    if (section.entropy >= 7.2 && section.sizeOfRawData >= 4096) {
      anomalies.push({
        id: "high-entropy-section",
        severity: "medium",
        detail: `区段 ${section.name || `#${section.index}`} 熵 ${section.entropy}（压缩/加密壳特征）`,
        rva: section.virtualAddress,
      });
    }
    if (!/^[.@/?$A-Za-z0-9_-]{1,8}$/.test(section.name) && section.name.length > 0) {
      anomalies.push({
        id: "unusual-section-name",
        severity: "low",
        detail: `区段名含非常规字符：${JSON.stringify(section.name)}`,
        rva: section.virtualAddress,
      });
    }
  }
  if (sectionByVa.length > 0) {
    for (let index = 1; index < sectionByVa.length; index += 1) {
      const previous = sectionByVa[index - 1];
      const current = sectionByVa[index];
      if (!previous || !current) continue;
      const previousEnd = previous.virtualAddress + Math.max(previous.virtualSize, previous.sizeOfRawData);
      if (current.virtualAddress < previousEnd) {
        anomalies.push({
          id: "overlapping-sections",
          severity: "medium",
          detail: `区段 ${current.name || `#${current.index}`} 与前一区段虚拟重叠`,
          rva: current.virtualAddress,
        });
      }
    }
  }
  if (imports.length > 0) {
    const importRva = importDirectory?.rva ?? 0;
    const iatRva = directory("iat")?.rva ?? 0;
    const iatSection = iatRva !== 0 ? sectionForRva(iatRva) : null;
    const importSection = sectionForRva(importRva);
    if (iatSection && importSection && iatSection.index !== importSection.index) {
      anomalies.push({
        id: "iat-outside-import-section",
        severity: "medium",
        detail: `IAT 位于 ${iatSection.name || `#${iatSection.index}`}，与导入表所在 ${importSection.name || `#${importSection.index}`} 不同（壳常搬移 IAT）`,
        rva: iatRva,
      });
    }
  }
  if (sections.length > 0) {
    const last = sections[sections.length - 1];
    if (last && entrySection && entrySection.index === last.index && sections.length >= 3) {
      anomalies.push({
        id: "entry-in-last-section",
        severity: "medium",
        detail: `入口点落在最后一个区段 ${last.name}（壳 stub 常见位置）`,
        rva: entryPointRva,
      });
    }
  }
  const computedChecksum = computePeChecksum(bytes, optionalOffset + 64);
  if (checksum !== 0 && computedChecksum !== checksum) {
    anomalies.push({
      id: "checksum-mismatch",
      severity: "low",
      detail: `校验和字段 ${toHex(checksum)} ≠ 计算值 ${toHex(computedChecksum)}（被修改/加壳后未修）`,
    });
  }

  return {
    source: { path: options.path ?? null, size: bytes.length, sha256: sha256Bytes(bytes) },
    dosMagic: 0x5a4d,
    peOffset,
    sectionTableOffset,
    optionalHeaderOffset: optionalOffset,
    machine,
    machineName: MACHINE_NAMES[machine] ?? `unknown-${toHex(machine, 4)}`,
    is64,
    numberOfSections,
    timeDateStamp,
    characteristics,
    optionalMagic,
    linkerVersion,
    osVersion,
    imageVersion,
    subsystemVersion,
    entryPointRva,
    entryPointVa: imageBase + entryPointRva,
    imageBase,
    sectionAlignment,
    fileAlignment,
    sizeOfImage,
    sizeOfHeaders,
    sizeOfCode,
    sizeOfInitializedData,
    checksum,
    computedChecksum,
    checksumValid: checksum === 0 || checksum === computedChecksum,
    subsystem,
    subsystemName: SUBSYSTEM_NAMES[subsystem] ?? `subsystem-${subsystem}`,
    dllCharacteristics,
    dll: (characteristics & 0x2000) !== 0,
    sections,
    dataDirectories,
    imports,
    delayImports,
    exports,
    tls,
    debug,
    resources,
    richHeader,
    overlay,
    clrRuntime,
    anomalies,
    coverage,
    binaryReader: reader,
  };
};

/** 便捷封装：从 RVA 取文件偏移（导出给上层模块复用同一张区段表）。 */
export const makeRvaResolver = (image: PeImage) => {
  const sorted = [...image.sections].sort((a, b) => a.virtualAddress - b.virtualAddress);
  const sectionForRva = (rva: number): PeSection | null => {
    for (const section of sorted) {
      const span = Math.max(section.virtualSize, section.sizeOfRawData);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span) return section;
    }
    return null;
  };
  const rvaToOffset = (rva: number): number | null => {
    if (rva < 0 || !Number.isFinite(rva)) return null;
    if (rva < Math.min(image.sizeOfHeaders, image.source.size)) return rva;
    const section = sectionForRva(rva);
    if (!section) return null;
    const delta = rva - section.virtualAddress;
    if (delta >= section.availableRawBytes) return null;
    return section.pointerToRawData + delta;
  };
  const offsetToRva = (offset: number): number | null => {
    for (const section of image.sections) {
      if (offset >= section.pointerToRawData && offset < section.pointerToRawData + section.availableRawBytes) {
        return section.virtualAddress + (offset - section.pointerToRawData);
      }
    }
    if (offset < Math.min(image.sizeOfHeaders, image.source.size)) return offset;
    return null;
  };
  return { sectionForRva, rvaToOffset, offsetToRva };
};

export const sumOfSectionEnd = (image: PeImage): number =>
  alignUp(
    image.sections.reduce((max, section) => Math.max(max, section.virtualAddress + Math.max(section.virtualSize, section.sizeOfRawData)), image.sizeOfHeaders),
    image.sectionAlignment || 0x1000,
  );
