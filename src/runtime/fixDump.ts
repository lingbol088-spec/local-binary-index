/**
 * 镜像修复：把「内存 dump」还原成「可被 RVA→偏移 解析的文件镜像」，
 * 并支持按补丁清单直接改写字节（反调试 NOP 等），全部在内存中完成。
 */
import type { PeImage } from "../pe/peFile.js";
import { parsePe, computePeChecksum } from "../pe/peFile.js";
import { alignUp, sha256Bytes, toHex } from "../util/bytes.js";

export interface DumpRepairOptions {
  readonly fileAlignment?: number;
  readonly sectionAlignment?: number;
  /** 强制按内存布局重排（即使自动检测认为已经是文件布局）。 */
  readonly forceMemoryLayout?: boolean;
}

export interface DumpRepairSection {
  readonly index: number;
  readonly name: string;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly sourceOffset: number;
  readonly copiedBytes: number;
  readonly newPointerToRawData: number;
  readonly newSizeOfRawData: number;
}

export interface FieldPatch {
  readonly field: string;
  readonly offset: number;
  readonly before: number;
  readonly after: number;
}

export interface DumpRepairResult {
  readonly ok: boolean;
  readonly memoryImage: boolean;
  readonly sha256Before: string;
  readonly sha256After: string;
  readonly originalSize: number;
  readonly repairedSize: number;
  readonly sections: readonly DumpRepairSection[];
  readonly patchedFields: readonly FieldPatch[];
  readonly warnings: readonly string[];
  readonly output: Uint8Array;
}

const isPowerOfTwo = (value: number): boolean => value > 0 && (value & (value - 1)) === 0;

export const isLikelyMemoryImage = (image: PeImage, bytes: Uint8Array): boolean => {
  const sections = image.sections;
  if (sections.length === 0) return false;
  const zeroPointer = sections.filter((section) => section.virtualSize > 0 && section.pointerToRawData === 0);
  if (zeroPointer.length === sections.length) return true;
  const virtualAddressed = sections.filter(
    (section) => section.virtualAddress !== 0 && section.pointerToRawData === section.virtualAddress,
  );
  if (virtualAddressed.length >= Math.ceil(sections.length / 2)) return true;
  const maxRawEnd = Math.max(
    image.sizeOfHeaders,
    ...sections.map((section) => section.pointerToRawData + section.sizeOfRawData),
  );
  return bytes.length >= image.sizeOfImage && maxRawEnd <= image.sizeOfHeaders + 0x400;
};

export const repairImageDump = (bytes: Uint8Array, options: DumpRepairOptions = {}): DumpRepairResult => {
  const image = parsePe(bytes);
  const warnings: string[] = [];
  const memoryImage = options.forceMemoryLayout === true || isLikelyMemoryImage(image, bytes);
  const fileAlignment =
    options.fileAlignment ?? (isPowerOfTwo(image.fileAlignment) ? image.fileAlignment : 0x200);
  const sectionAlignment =
    options.sectionAlignment ?? (isPowerOfTwo(image.sectionAlignment) ? image.sectionAlignment : 0x1000);

  const headerSize = alignUp(
    Math.max(image.sizeOfHeaders, image.sectionTableOffset + image.sections.length * 40),
    fileAlignment,
  );

  const sourceFor = (section: PeImage["sections"][number]): number => {
    if (!memoryImage) return section.pointerToRawData;
    // 内存镜像里区段位于其 RVA；若 dump 仍是文件布局（指针合法），退回原指针
    const pointer = section.pointerToRawData;
    const pointerLooksValid =
      pointer !== 0 &&
      pointer !== section.virtualAddress &&
      pointer < bytes.length &&
      pointer + Math.min(section.sizeOfRawData, 16) <= bytes.length;
    return pointerLooksValid ? pointer : section.virtualAddress;
  };

  let cursor = headerSize;
  const plans: {
    section: PeImage["sections"][number];
    sourceOffset: number;
    copiedBytes: number;
    rawSize: number;
    newPointer: number;
  }[] = [];

  for (const section of image.sections) {
    const declared = section.virtualSize > 0 ? section.virtualSize : section.sizeOfRawData;
    const available = Math.max(0, Math.min(declared, bytes.length - sourceFor(section)));
    if (available < declared) {
      warnings.push(
        `区段 ${section.name || `#${section.index}`} 声明 ${declared} 字节，dump 内仅可用 ${available} 字节（已按可用长度写出）`,
      );
    }
    const rawSize = alignUp(available, fileAlignment);
    const newPointer = alignUp(cursor, fileAlignment);
    plans.push({ section, sourceOffset: sourceFor(section), copiedBytes: available, rawSize, newPointer });
    cursor = newPointer + rawSize;
  }

  const output = Buffer.alloc(cursor);
  Buffer.from(bytes.buffer, bytes.byteOffset, Math.min(headerSize, bytes.length)).copy(output, 0);

  const sections: DumpRepairSection[] = [];
  for (const plan of plans) {
    const slice = Buffer.from(
      bytes.buffer,
      bytes.byteOffset + plan.sourceOffset,
      plan.copiedBytes,
    );
    slice.copy(output, plan.newPointer);
    // 写回区段头：SizeOfRawData 与 PointerToRawData
    const headerOffset = image.sectionTableOffset + plan.section.index * 40;
    output.writeUInt32LE(plan.rawSize, headerOffset + 16);
    output.writeUInt32LE(plan.newPointer, headerOffset + 20);
    sections.push({
      index: plan.section.index,
      name: plan.section.name,
      virtualAddress: plan.section.virtualAddress,
      virtualSize: plan.section.virtualSize,
      sourceOffset: plan.sourceOffset,
      copiedBytes: plan.copiedBytes,
      newPointerToRawData: plan.newPointer,
      newSizeOfRawData: plan.rawSize,
    });
  }

  const patchedFields: FieldPatch[] = [];
  const patchField = (field: string, offset: number, value: number): void => {
    const before = output.readUInt32LE(offset);
    if (before === value) return;
    output.writeUInt32LE(value, offset);
    patchedFields.push({ field, offset, before, after: value });
  };

  const maxVirtualEnd = image.sections.reduce(
    (max, section) => Math.max(max, section.virtualAddress + Math.max(section.virtualSize, section.sizeOfRawData)),
    headerSize,
  );
  const alignedImageSize = alignUp(maxVirtualEnd, sectionAlignment);
  patchField("SizeOfImage", image.optionalHeaderOffset + 56, alignedImageSize > 0 ? alignedImageSize : image.sizeOfImage);
  patchField("SizeOfHeaders", image.optionalHeaderOffset + 60, headerSize);

  // 校验和：先归零再计算
  output.writeUInt32LE(0, image.optionalHeaderOffset + 64);
  const checksum = computePeChecksum(output, image.optionalHeaderOffset + 64);
  output.writeUInt32LE(checksum, image.optionalHeaderOffset + 64);
  patchedFields.push({
    field: "CheckSum",
    offset: image.optionalHeaderOffset + 64,
    before: image.checksum,
    after: checksum,
  });

  // 自校验：修复后的镜像必须能被解析，且入口点仍落在可执行区段内
  const reparsed = parsePe(output);
  const entrySection = reparsed.sections.find((section) => {
    const span = Math.max(section.virtualSize, section.sizeOfRawData);
    return reparsed.entryPointRva >= section.virtualAddress && reparsed.entryPointRva < section.virtualAddress + span;
  });
  if (!entrySection) {
    warnings.push(`入口点 ${toHex(reparsed.entryPointRva)} 修复后不落在任何区段：dump 可能不完整`);
  } else if (!entrySection.flags.executable) {
    warnings.push(`入口点落在非可执行区段 ${entrySection.name}：区段权限可能被抹掉`);
  }
  if (reparsed.sizeOfImage < image.sizeOfImage / 2) {
    warnings.push("修复后 SizeOfImage 显著变小：检查是否把内存镜像当成了文件镜像");
  }

  return {
    ok: true,
    memoryImage,
    sha256Before: sha256Bytes(bytes),
    sha256After: sha256Bytes(output),
    originalSize: bytes.length,
    repairedSize: output.length,
    sections,
    patchedFields,
    warnings,
    output: new Uint8Array(output.buffer, output.byteOffset, output.byteLength),
  };
};

export interface BytePatch {
  readonly fileOffset: number;
  readonly bytes: string;
  readonly reason: string;
}

export interface PatchApplyResult {
  readonly applied: readonly { readonly fileOffset: number; readonly bytes: string; readonly before: string; readonly after: string; readonly reason: string; readonly verified: boolean }[];
  readonly rejected: readonly { readonly fileOffset: number; readonly reason: string; readonly detail: string }[];
  readonly output: Uint8Array;
  readonly sha256Before: string;
  readonly sha256After: string;
}

export const applyBytePatches = (bytes: Uint8Array, patches: readonly BytePatch[]): PatchApplyResult => {
  const output = Buffer.from(bytes);
  const applied: PatchApplyResult["applied"][number][] = [];
  const rejected: PatchApplyResult["rejected"][number][] = [];

  for (const patch of patches) {
    const patchBytes = patch.bytes
      .trim()
      .split(/\s+/)
      .filter((token) => token.length > 0)
      .map((token) => Number.parseInt(token, 16));
    if (patchBytes.length === 0 || patchBytes.some((value) => Number.isNaN(value))) {
      rejected.push({ fileOffset: patch.fileOffset, reason: patch.reason, detail: "补丁字节无法解析" });
      continue;
    }
    if (patch.fileOffset < 0 || patch.fileOffset + patchBytes.length > output.length) {
      rejected.push({ fileOffset: patch.fileOffset, reason: patch.reason, detail: "越界：补丁会写到文件之外" });
      continue;
    }
    const before = output.subarray(patch.fileOffset, patch.fileOffset + patchBytes.length);
    const beforeHex = Array.from(before, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
    patchBytes.forEach((value, index) => {
      output[patch.fileOffset + index] = value;
    });
    const after = output.subarray(patch.fileOffset, patch.fileOffset + patchBytes.length);
    const afterHex = Array.from(after, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ");
    applied.push({
      fileOffset: patch.fileOffset,
      bytes: patch.bytes,
      before: beforeHex,
      after: afterHex,
      reason: patch.reason,
      verified: afterHex === patchBytes.map((value) => value.toString(16).toUpperCase().padStart(2, "0")).join(" "),
    });
  }

  return {
    applied,
    rejected,
    output: new Uint8Array(output.buffer, output.byteOffset, output.byteLength),
    sha256Before: sha256Bytes(bytes),
    sha256After: sha256Bytes(output),
  };
};
