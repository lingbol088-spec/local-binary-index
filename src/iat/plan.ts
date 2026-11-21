/**
 * IAT 重建规划：现状测绘 + 残留描述符扫描 + 重建蓝图 + 落地命令。
 * 只做静态可证部分；真值必须由运行时 dump 后的内存镜像提供。
 */
import type { PeImage } from "../pe/peFile.js";
import { makeRvaResolver } from "../pe/peFile.js";
import { toHex } from "../util/bytes.js";

export interface IatSlot {
  readonly dll: string;
  readonly name: string | null;
  readonly ordinal: number | null;
  readonly iatRva: number;
  readonly iatVa: number;
}

export interface DescriptorCandidate {
  readonly arrayRva: number;
  readonly moduleNames: readonly string[];
  readonly terminated: boolean;
  readonly score: number;
  readonly note: string;
}

export interface IatPlanResult {
  readonly current: {
    readonly moduleCount: number;
    readonly functionCount: number;
    readonly ordinalOnlyCount: number;
    readonly iatRva: number | null;
    readonly iatSize: number | null;
    readonly iatSection: string | null;
    readonly importSection: string | null;
    readonly iatDiverseFromImportSection: boolean;
    readonly usedSlotRange: { readonly first: number; readonly last: number } | null;
  };
  readonly slots: readonly IatSlot[];
  readonly descriptorCandidates: readonly DescriptorCandidate[];
  readonly blueprint: readonly { readonly dll: string; readonly functionCount: number; readonly slots: readonly IatSlot[] }[];
  readonly rebuildSteps: readonly string[];
  readonly tooling: {
    readonly scyllaCommand: string;
    readonly x64dbgDumpScript: readonly string[];
    readonly notes: readonly string[];
  };
  readonly limitations: readonly string[];
}

const MODULE_NAME_PATTERN = /^[A-Za-z0-9_.\- ]{2,64}\.(dll|DLL|ocx|OCX|sys|SYS|drv|DRV|exe|EXE)$/;

export const planIatRebuild = (image: PeImage, bytes: Uint8Array): IatPlanResult => {
  const resolver = makeRvaResolver(image);
  const slots: IatSlot[] = [];
  for (const module of [...image.imports, ...image.delayImports]) {
    for (const fn of module.functions) {
      slots.push({
        dll: module.name,
        name: fn.name,
        ordinal: fn.ordinal,
        iatRva: fn.iatRva,
        iatVa: fn.iatVa,
      });
    }
  }
  const functionCount = slots.length;
  const ordinalOnlyCount = slots.filter((slot) => slot.name === null).length;

  const iatDirectory = image.dataDirectories.find((entry) => entry.name === "iat" && entry.rva !== 0) ?? null;
  const importDirectory = image.dataDirectories.find((entry) => entry.name === "import" && entry.rva !== 0) ?? null;
  const iatSection = iatDirectory ? resolver.sectionForRva(iatDirectory.rva) : null;
  const importSection = importDirectory ? resolver.sectionForRva(importDirectory.rva) : null;
  const stride = image.is64 ? 8 : 4;
  const slotIndices = slots
    .map((slot) => Math.floor(slot.iatRva / stride))
    .filter((value) => Number.isFinite(value));
  const usedSlotRange =
    slotIndices.length === 0
      ? null
      : { first: Math.min(...slotIndices), last: Math.max(...slotIndices) };

  // ---- 残留导入描述符扫描 ----
  const descriptorCandidates: DescriptorCandidate[] = [];
  for (const section of image.sections) {
    if (section.availableRawBytes < 20) continue;
    const start = section.pointerToRawData;
    const end = start + section.availableRawBytes;
    const reader = image.binaryReader;
    for (let offset = start; offset + 20 <= end; offset += 4) {
      const ilt = reader.u32(offset);
      const timestamp = reader.u32(offset + 4);
      const forwarder = reader.u32(offset + 8);
      const nameRva = reader.u32(offset + 12);
      const firstThunk = reader.u32(offset + 16);
      void timestamp;
      void forwarder;
      if (ilt === 0 && firstThunk === 0) continue;
      if (nameRva === 0 || nameRva > image.sizeOfImage) continue;
      const nameOffset = resolver.rvaToOffset(nameRva);
      if (nameOffset === null) continue;
      const dllName = reader.cstring(nameOffset, 64);
      if (!MODULE_NAME_PATTERN.test(dllName)) continue;

      const moduleNames: string[] = [];
      let cursor = offset;
      let terminated = false;
      for (let index = 0; index < 256; index += 1) {
        if (cursor + 20 > end) break;
        const descriptorIlt = reader.u32(cursor);
        const descriptorNameRva = reader.u32(cursor + 12);
        const descriptorFirstThunk = reader.u32(cursor + 16);
        if (descriptorIlt === 0 && descriptorNameRva === 0 && descriptorFirstThunk === 0) {
          terminated = true;
          break;
        }
        const descriptorNameOffset = resolver.rvaToOffset(descriptorNameRva);
        if (descriptorNameOffset === null) break;
        const descriptorName = reader.cstring(descriptorNameOffset, 64);
        if (!MODULE_NAME_PATTERN.test(descriptorName)) break;
        moduleNames.push(descriptorName);
        cursor += 20;
      }
      if (moduleNames.length === 0) continue;

      const arrayRva = resolver.offsetToRva(offset);
      if (arrayRva === null) continue;
      // 已声明的导入表本身不重复计数
      if (importDirectory && Math.abs(arrayRva - importDirectory.rva) < 20) continue;
      const alreadyKnown = descriptorCandidates.some(
        (candidate) => Math.abs(candidate.arrayRva - arrayRva) < 20,
      );
      if (alreadyKnown) continue;

      const score = Math.min(
        100,
        moduleNames.length * 12 + (terminated ? 18 : 0) + (ilt !== 0 ? 12 : 0) + (firstThunk !== 0 ? 12 : 0),
      );
      descriptorCandidates.push({
        arrayRva,
        moduleNames,
        terminated,
        score,
        note: `${moduleNames.length} 个模块描述符${terminated ? "（有 0 结尾）" : "（未见 0 结尾，可能被截断）"} @ ${toHex(arrayRva)}`,
      });
      if (descriptorCandidates.length >= 32) break;
    }
    if (descriptorCandidates.length >= 32) break;
  }
  descriptorCandidates.sort((left, right) => right.score - left.score);

  // ---- 蓝图 ----
  const blueprint = [...new Set(slots.map((slot) => slot.dll))]
    .filter((dll) => dll.length > 0)
    .map((dll) => {
      const moduleSlots = slots.filter((slot) => slot.dll === dll);
      return { dll, functionCount: moduleSlots.length, slots: moduleSlots };
    });

  const rebuildSteps: string[] = [
    "1) 在 OEP 断点命中、且目标区段已解压（内存里可执行区段熵下降）后再 dump，过早 dump 只能拿到壳的 stub",
    "2) dump 落盘后先修区段表（本工具的 fix-dump 子命令），否则文件无法被 RVA→偏移解析",
    "3) IAT 重建优先级：① 二进制残留的原始描述符（见 descriptorCandidates）→ ② Scylla 自动扫描 → ③ 手工记录调用点",
    "4) 校验：重建后所有导入函数名可解析、且 IAT 槽位按调用约定可读；再跑一次本工具确认 imports 非空且无 ordinal-only 泛滥",
    "5) 若仍有 ordinal-only 导入，按序数在对应系统 DLL 的导出表反查名字补全",
  ];
  if (descriptorCandidates.length > 0) {
    rebuildSteps.push(
      `6) 已发现 ${descriptorCandidates.length} 组疑似原始导入描述符，最高分位于 ${toHex(descriptorCandidates[0]?.arrayRva ?? 0)}（${descriptorCandidates[0]?.moduleNames.slice(0, 4).join(",") ?? ""}）`,
    );
  }

  const tooling = {
    scyllaCommand: [
      "Scylla.exe",
      "-a",
      "-p <PID>",
      "-o <OUT_DUMP_FIXED.exe>",
      `--iat ${toHex(iatDirectory?.rva ?? 0)}`,
      `--oep ${toHex(image.entryPointRva)}`,
    ].join(" "),
    x64dbgDumpScript: [
      "// 到达 OEP 之后执行（x64dbg 命令栏 / 脚本）",
      "dump <模块基址>",
      "// 或：在内存窗口选中模块 → 右键 → Dump to file",
      "// 然后用 Scylla 附加进程，IAT Autosearch → Get Imports → Fix Dump",
    ],
    notes: [
      "Scylla 的参数名随版本略有差异；上命令是 2.x 形态，请按 --help 校对",
      "x64dbg 自带的 Scylla 插件可直接在 OEP 处右键 Scylla",
      "ordinal-only 导入（本文件 " + String(ordinalOnlyCount) + " 个）是重建时的主要难点",
    ],
  };

  const limitations = [
    "静态扫描只能发现「还在文件里」的原始描述符；被壳搬走/加密的原表必须在内存镜像里找",
    "IAT 槽位的真实函数名需运行时解析（LoadLibrary/GetProcAddress 的结果才是权威）",
    "本模块不写文件、不 patch 输入；落地由 fix-dump 与外部工具完成",
  ];

  return {
    current: {
      moduleCount: blueprint.length,
      functionCount,
      ordinalOnlyCount,
      iatRva: iatDirectory?.rva ?? null,
      iatSize: iatDirectory?.size ?? null,
      iatSection: iatSection ? iatSection.name || `#${iatSection.index}` : null,
      importSection: importSection ? importSection.name || `#${importSection.index}` : null,
      iatDiverseFromImportSection: Boolean(
        iatSection && importSection && iatSection.index !== importSection.index,
      ),
      usedSlotRange,
    },
    slots,
    descriptorCandidates,
    blueprint,
    rebuildSteps,
    tooling,
    limitations,
  };
};
