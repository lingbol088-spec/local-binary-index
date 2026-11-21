import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { analyzeFile } from "../src/index.js";
import { parsePe } from "../src/pe/peFile.js";
import { repairImageDump, applyBytePatches } from "../src/runtime/fixDump.js";
import { decodeInstruction } from "../src/oep/x86len.js";
import { isActivated } from "../src/activation.js";

const samplePath = join(process.cwd(), "fixtures", "packed-sample.exe");
const dumpPath = join(process.cwd(), "fixtures", "memory-dump.bin");
const sampleBytes = new Uint8Array(readFileSync(samplePath));

test("PE 结构解析：头部/区段/导入/TLS/overlay", () => {
  const image = parsePe(sampleBytes, { path: samplePath });
  assert.equal(image.machineName, "i386");
  assert.equal(image.is64, false);
  assert.equal(image.sections.length, 4);
  assert.equal(image.entryPointRva, 0x4000);
  assert.equal(image.entryPointVa, 0x404000);
  assert.equal(image.imports.length, 1);
  assert.equal(image.imports[0]?.name, "KERNEL32.dll");
  assert.equal(image.imports[0]?.functions.length, 3);
  assert.deepEqual(
    image.imports[0]?.functions.map((fn) => fn.name),
    ["IsDebuggerPresent", "VirtualProtect", "GetTickCount"],
  );
  assert.equal(image.tls?.callbackRvas.length, 1);
  assert.equal(image.overlay?.markers.includes("UPX!"), true);
  assert.equal(image.anomalies.some((anomaly) => anomaly.id === "virtual-only-section"), true);
});

test("保护识别：判定为 UPX 压缩壳", () => {
  const analysis = analyzeFile(samplePath);
  assert.equal(analysis.protection.verdict, "packed");
  assert.equal(analysis.protection.primaryFamily, "UPX");
  assert.ok(analysis.protection.confidence >= 0.9);
  const upx = analysis.protection.families.find((family) => family.id === "upx");
  assert.ok(upx);
  assert.ok(upx.signals.some((signal) => signal.kind === "section-name"));
  assert.ok(upx.signals.some((signal) => signal.kind === "byte-pattern"));
  assert.ok(upx.signals.some((signal) => signal.kind === "overlay-marker"));
});

test("OEP 猎人：tail jump 命中 0x401000，ESP 定律可用", () => {
  const analysis = analyzeFile(samplePath);
  assert.ok(analysis.entryTransfer.best);
  assert.equal(analysis.entryTransfer.best?.va, 0x401000);
  assert.equal(analysis.entryTransfer.best?.origin, "push-ret");
  assert.ok((analysis.entryTransfer.best?.score ?? 0) >= 90);
  assert.equal(analysis.entryTransfer.espLaw.applicable, true);
  assert.ok(analysis.entryTransfer.breakpoints.some((bp) => bp.kind === "oep-candidate"));
  assert.equal(analysis.entryTransfer.stub.pushadOffset !== null, true);
});

test("导入重建：现状 + 残留描述符被找到", () => {
  const analysis = analyzeFile(samplePath);
  assert.equal(analysis.imports.current.moduleCount, 1);
  assert.equal(analysis.imports.current.functionCount, 3);
  assert.equal(analysis.imports.current.ordinalOnlyCount, 0);
  assert.ok(analysis.imports.descriptorCandidates.length >= 1);
  const residual = analysis.imports.descriptorCandidates[0];
  assert.ok(residual?.moduleNames.includes("USER32.dll"));
  assert.ok(residual?.moduleNames.includes("GDI32.dll"));
  assert.ok(analysis.imports.rebuildSteps.length >= 5);
});

test("反分析：int 2d / icebp / IAT hook 目标", () => {
  const analysis = analyzeFile(samplePath);
  const ids = new Set(analysis.antiAnalysis.findings.map((finding) => finding.id));
  assert.ok(ids.has("int2d"));
  assert.ok(ids.has("icebp"));
  assert.ok(ids.has("tls-callback"));
  const hook = analysis.antiAnalysis.hookTargets.find((target) => target.api === "IsDebuggerPresent");
  assert.ok(hook);
  assert.equal(hook?.iatVa, 0x405200);
  assert.ok(analysis.patchList.length >= 2);
  for (const patch of analysis.patchList) {
    assert.match(patch.bytes, /^(90 ?)+$/);
  }
});

test("托管层：非 .NET 返回 isManaged=false", () => {
  const analysis = analyzeFile(samplePath);
  assert.equal(analysis.managed.isManaged, false);
});

test("dump 修复：内存布局 → 文件布局，并重算校验和", () => {
  const dump = new Uint8Array(readFileSync(dumpPath));
  const repaired = repairImageDump(dump);
  assert.equal(repaired.ok, true);
  assert.equal(repaired.memoryImage, true);
  assert.notEqual(repaired.sha256Before, repaired.sha256After);
  assert.ok(repaired.repairedSize < dump.length);
  const reparsed = parsePe(repaired.output);
  assert.equal(reparsed.entryPointRva, 0x4000);
  const second = reparsed.sections[1];
  assert.ok(second !== undefined);
  assert.ok(second.pointerToRawData > 0);
  assert.equal(second.sizeOfRawData % 0x200, 0);
  assert.ok(reparsed.checksum !== 0);
  assert.equal(reparsed.imports.length, 1);
  assert.ok(repaired.patchedFields.some((field) => field.field === "CheckSum"));
});

test("补丁落地：NOP 覆盖并回读校验", () => {
  const analysis = analyzeFile(samplePath);
  const int2d = analysis.antiAnalysis.findings.find((finding) => finding.id === "int2d");
  assert.ok(int2d?.fileOffset !== null && int2d?.fileOffset !== undefined);
  const result = applyBytePatches(sampleBytes, [
    { fileOffset: int2d?.fileOffset ?? 0, bytes: "90 90", reason: "nop int2d" },
    { fileOffset: 0xfffffff0, bytes: "90", reason: "越界补丁" },
  ]);
  assert.equal(result.applied.length, 1);
  assert.equal(result.applied[0]?.verified, true);
  assert.equal(result.applied[0]?.after, "90 90");
  assert.equal(result.rejected.length, 1);
  assert.notEqual(result.sha256Before, result.sha256After);
});

test("指令解码：关键 stub 序列长度与语义", () => {
  const image = parsePe(sampleBytes);
  const entry = image.sections.find((section) => section.name === "UPX1")?.pointerToRawData ?? 0;
  const first = decodeInstruction(sampleBytes, entry, { is64: false });
  assert.equal(first.kind, "pushad");
  assert.equal(first.length, 1);
  const movEsi = decodeInstruction(sampleBytes, entry + 1, { is64: false });
  assert.equal(movEsi.length, 5);
  const lea = decodeInstruction(sampleBytes, entry + 6, { is64: false });
  assert.equal(lea.length, 6);
  const call = decodeInstruction(sampleBytes, entry + 19, { is64: false });
  assert.equal(call.kind, "call-rm");
  assert.equal(call.memoryAddress, 0x405200);
  assert.equal(call.length, 6);
  const pushImm = decodeInstruction(sampleBytes, entry + 25, { is64: false });
  assert.equal(pushImm.kind, "push-imm32");
  assert.equal(pushImm.immediate, 0x401000);
  const ret = decodeInstruction(sampleBytes, entry + 30, { is64: false });
  assert.equal(ret.kind, "ret");
});

test("触发词门控：只有 zxwn 激活", () => {
  const previousStateDir = process.env.LBI_STATE_DIR;
  process.env.LBI_STATE_DIR = join(tmpdir(), `lbi-test-${process.pid}-${Date.now()}`);
  try {
  assert.equal(isActivated({}), false);
  assert.equal(isActivated({ LBI_TOKEN: "zxwn" }), true);
  assert.equal(isActivated({ LBI_TOKEN: "nope" }), false);
  assert.equal(isActivated({ OTHER: "zxwn" }), false);
  } finally {
    if (previousStateDir === undefined) delete process.env.LBI_STATE_DIR;
    else process.env.LBI_STATE_DIR = previousStateDir;
  }
});
