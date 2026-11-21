/**
 * 托管代码（.NET）保护分析：CLR 头 → 元数据根 → 流表 → 表行数 → 混淆指纹。
 * 不加载程序集、不反序列化、不执行 IL。
 */
import type { PeImage } from "../pe/peFile.js";
import { makeRvaResolver } from "../pe/peFile.js";
import { toHex } from "../util/bytes.js";

export interface ManagedStream {
  readonly name: string;
  readonly offset: number;
  readonly size: number;
}

export interface ObfuscatorMarker {
  readonly family: string;
  readonly marker: string;
  readonly stream: string;
  readonly streamOffset: number;
}

export interface ManagedProtectionReport {
  readonly isManaged: boolean;
  readonly runtimeVersion: string | null;
  readonly metadataVersion: string | null;
  readonly entryPointToken: number | null;
  readonly streams: readonly ManagedStream[];
  readonly tableRowCounts: Readonly<Record<string, number>>;
  readonly totals: {
    readonly typeDefs: number;
    readonly methods: number;
    readonly fields: number;
    readonly memberRefs: number;
    readonly assemblyRefs: number;
  };
  readonly obfuscatorMarkers: readonly ObfuscatorMarker[];
  readonly indicators: readonly string[];
  readonly steps: readonly string[];
  readonly limitations: readonly string[];
}

const TABLE_NAMES: readonly string[] = [
  "Module",
  "TypeRef",
  "TypeDef",
  "FieldPtr",
  "Field",
  "MethodPtr",
  "MethodDef",
  "ParamPtr",
  "Param",
  "InterfaceImpl",
  "MemberRef",
  "Constant",
  "CustomAttribute",
  "FieldMarshal",
  "DeclSecurity",
  "ClassLayout",
  "FieldLayout",
  "StandAloneSig",
  "EventMap",
  "EventPtr",
  "Event",
  "PropertyMap",
  "PropertyPtr",
  "Property",
  "MethodSemantics",
  "MethodImpl",
  "ModuleRef",
  "TypeSpec",
  "ImplMap",
  "FieldRVA",
  "ENCLog",
  "ENCMap",
  "Assembly",
  "AssemblyProcessor",
  "AssemblyOS",
  "AssemblyRef",
  "AssemblyRefProcessor",
  "AssemblyRefOS",
  "File",
  "ExportedType",
  "ManifestResource",
  "NestedClass",
  "GenericParam",
  "MethodSpec",
  "GenericParamConstraint",
];

const OBFUSCATOR_FINGERPRINTS: readonly { readonly family: string; readonly marker: string }[] = [
  { family: "ConfuserEx", marker: "ConfusedBy" },
  { family: "ConfuserEx", marker: "ConfuserEx" },
  { family: "ConfuserEx", marker: "Confuser.Core" },
  { family: "ConfuserEx", marker: "ConfusedByAttribute" },
  { family: ".NET Reactor", marker: "NET Reactor" },
  { family: ".NET Reactor", marker: "Reactor" },
  { family: "SmartAssembly", marker: "SmartAssembly" },
  { family: "Dotfuscator", marker: "Dotfuscator" },
  { family: "Dotfuscator", marker: "PreEmptive" },
  { family: "Eazfuscator", marker: "Eazfuscator" },
  { family: "Babel", marker: "Babel Obfuscator" },
  { family: "KoiVM", marker: "KoiVM" },
  { family: "Agile.NET", marker: "Agile.NET" },
  { family: "CryptoObfuscator", marker: "CryptoObfuscator" },
  { family: "MaxToCode", marker: "MaxToCode" },
  { family: "Themida/.NET", marker: "Themida" },
  { family: "VMProtect/.NET", marker: "VMProtect" },
  { family: "Obfuscar", marker: "Obfuscar" },
];

const NON_ASCII_NAME = /[^\x20-\x7e]/;

export const analyzeManaged = (image: PeImage, bytes: Uint8Array): ManagedProtectionReport => {
  const empty: ManagedProtectionReport = {
    isManaged: false,
    runtimeVersion: null,
    metadataVersion: null,
    entryPointToken: null,
    streams: [],
    tableRowCounts: {},
    totals: { typeDefs: 0, methods: 0, fields: 0, memberRefs: 0, assemblyRefs: 0 },
    obfuscatorMarkers: [],
    indicators: [],
    steps: ["不是 .NET 程序集：CLR 目录缺失或 CLR 头不可解析"],
    limitations: [],
  };
  if (!image.clrRuntime) return empty;

  const resolver = makeRvaResolver(image);
  const reader = image.binaryReader;
  const metadataRva = image.clrRuntime.metaDataRva;
  const metadataOffset = resolver.rvaToOffset(metadataRva);
  if (metadataOffset === null) {
    return {
      ...empty,
      isManaged: true,
      entryPointToken: image.clrRuntime.entryPointToken,
      limitations: [`元数据 RVA ${toHex(metadataRva)} 无法映射到文件偏移`],
    };
  }

  const signature = reader.u32(metadataOffset);
  if (signature !== 0x424a5342) {
    return {
      ...empty,
      isManaged: true,
      limitations: [`元数据签名非 BSJB（实际 ${toHex(signature)}）`],
    };
  }

  const majorVersion = reader.u16(metadataOffset + 4);
  const minorVersion = reader.u16(metadataOffset + 6);
  const versionLength = reader.u32(metadataOffset + 12);
  const versionString = Buffer.from(
    reader.bytes(metadataOffset + 16, Math.min(versionLength, 256)),
  )
    .toString("utf8")
    .replace(/\0+$/, "");
  const streamCountOffset = metadataOffset + 16 + Math.ceil(versionLength / 4) * 4;
  const streamCount = reader.u16(streamCountOffset + 2);

  const streams: ManagedStream[] = [];
  let cursor = streamCountOffset + 4;
  for (let index = 0; index < Math.min(streamCount, 16); index += 1) {
    if (!reader.has(cursor, 8)) break;
    const offset = reader.u32(cursor);
    const size = reader.u32(cursor + 4);
    let nameEnd = cursor + 8;
    while (nameEnd < reader.length && reader.u8(nameEnd) !== 0) nameEnd += 1;
    const name = reader.ascii(cursor + 8, Math.max(0, nameEnd - (cursor + 8)));
    streams.push({ name, offset, size });
    const nameBytes = name.length + 1;
    cursor = cursor + 8 + Math.ceil(nameBytes / 4) * 4;
  }

  const streamByName = (name: string): ManagedStream | null =>
    streams.find((stream) => stream.name === name) ?? null;

  const tableRowCounts: Record<string, number> = {};
  const metaStream = streamByName("#~") ?? streamByName("#-");
  if (metaStream) {
    const tableOffset = metadataOffset + metaStream.offset;
    if (reader.has(tableOffset, 24)) {
      const valid = reader.u64(tableOffset + 8);
      let rowCursor = tableOffset + 24;
      for (let tableIndex = 0; tableIndex < 64; tableIndex += 1) {
        const flag = 1n << BigInt(tableIndex);
        if ((valid & flag) === 0n) continue;
        if (!reader.has(rowCursor, 4)) break;
        const rows = reader.u32(rowCursor);
        rowCursor += 4;
        const name = TABLE_NAMES[tableIndex] ?? `Table${tableIndex}`;
        tableRowCounts[name] = rows;
      }
    }
  }

  // #Strings：混淆器标记与名字质量
  const obfuscatorMarkers: ObfuscatorMarker[] = [];
  const indicators: string[] = [];
  const stringsStream = streamByName("#Strings");
  if (stringsStream) {
    const start = metadataOffset + stringsStream.offset;
    const end = Math.min(reader.length, start + stringsStream.size);
    const text = Buffer.from(reader.bytes(start, end - start)).toString("latin1");
    for (const fingerprint of OBFUSCATOR_FINGERPRINTS) {
      const index = text.indexOf(fingerprint.marker);
      if (index < 0) continue;
      obfuscatorMarkers.push({
        family: fingerprint.family,
        marker: fingerprint.marker,
        stream: "#Strings",
        streamOffset: index,
      });
    }
    const names = text.split("\0").filter((name) => name.length > 0);
    const weird = names.filter((name) => NON_ASCII_NAME.test(name));
    const ratio = names.length === 0 ? 0 : weird.length / names.length;
    if (ratio >= 0.25 && names.length >= 20) {
      indicators.push(
        `#Strings 中 ${weird.length}/${names.length}（${(ratio * 100).toFixed(1)}%）标识符含非 ASCII 字符：重命名型混淆`,
      );
    }
    if (text.includes("<PrivateImplementationDetails>")) {
      indicators.push("#Strings 含 <PrivateImplementationDetails>：常量/字符串加密常见宿主类型");
    }
  }
  const userStrings = streamByName("#US");
  if (userStrings && userStrings.size < 64 && (tableRowCounts.MethodDef ?? 0) > 50) {
    indicators.push("#US 流近乎为空但方法数量大：用户字符串大概率被加密");
  }
  if (bytes.length > 0 && image.sections.some((section) => section.name === ".sdata" || section.name === ".net" )) {
    const weird = image.sections.filter((section) => section.name.startsWith(".s") && section.flags.executable);
    if (weird.length > 0) indicators.push("存在可执行的非标准 .s* 区段：托管方法体可能被 native 化");
  }
  if ((tableRowCounts.MethodDef ?? 0) > 0 && (tableRowCounts.TypeDef ?? 0) > 0) {
    const perType = (tableRowCounts.MethodDef ?? 0) / (tableRowCounts.TypeDef ?? 1);
    if (perType > 24) indicators.push(`平均每类型 ${perType.toFixed(1)} 个方法：可能是控制流混淆/方法摊平`);
  }
  if (obfuscatorMarkers.length > 0) {
    indicators.push(
      `命中混淆器标记：${[...new Set(obfuscatorMarkers.map((marker) => marker.family))].join(", ")}`,
    );
  }

  const totals = {
    typeDefs: tableRowCounts.TypeDef ?? 0,
    methods: tableRowCounts.MethodDef ?? 0,
    fields: tableRowCounts.Field ?? 0,
    memberRefs: tableRowCounts.MemberRef ?? 0,
    assemblyRefs: tableRowCounts.AssemblyRef ?? 0,
  };

  const steps: string[] = [
    "1) 静态看结构：#~ 表行数、#Strings 质量、#US 体积决定混淆强度",
    "2) de4dot 去混淆（先识别变体：`de4dot -f <file>`），保留输出为 <name>-cleaned.exe",
    "3) 字符串解密：定位模块初始化（.cctor / 委托解密器），用 dnSpy 在初始化后 dump 内存中的字符串",
    "4) 若方法体被 native 化：先按原生壳处理（dump + IAT 重建），再回到托管层解读",
    "5) 反篡改/反调试：先 patch 校验入口，再挂调试器",
  ];
  if (obfuscatorMarkers.some((marker) => marker.family === "ConfuserEx")) {
    steps.push("6) ConfuserEx 专用：常量解密可复用公开的 ConfuserEx-Unpacker 流程（按版本选）");
  }

  return {
    isManaged: true,
    runtimeVersion: image.clrRuntime ? `v${majorVersion}.${minorVersion}` : null,
    metadataVersion: versionString.length > 0 ? versionString : null,
    entryPointToken: image.clrRuntime.entryPointToken,
    streams,
    tableRowCounts,
    totals,
    obfuscatorMarkers,
    indicators,
    steps,
    limitations: [
      "未解析 #Blob/#US 内容，未还原 IL；表行数来自 #~ 头，不校验行宽",
      "混淆器识别基于字符串标记，去品牌化的商业壳可能只留行为特征",
      "未覆盖：单文件 bundle 内嵌程序集（先拆 bundle 再分析）",
    ],
  };
};
