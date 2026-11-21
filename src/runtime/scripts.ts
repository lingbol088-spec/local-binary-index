/**
 * 落地脚本生成：x64dbg / gdb / WinDbg / Frida / Scylla。
 * 生成物是纯文本，可直接保存执行；所有地址按 ImageBase 计算，ASLR 场景见脚本内说明。
 */
import type { PeImage } from "../pe/peFile.js";
import type { OepHuntResult } from "../oep/hunt.js";
import type { IatPlanResult } from "../iat/plan.js";
import type { AntiAnalysisResult } from "../antidebug/scan.js";
import type { PackerDetection } from "../packer/detect.js";
import { toHex } from "../util/bytes.js";

export interface EmitInput {
  readonly image: PeImage;
  readonly oep: OepHuntResult;
  readonly iat: IatPlanResult;
  readonly anti: AntiAnalysisResult;
  readonly packer: PackerDetection;
}

export interface ScriptBundle {
  readonly x64dbg: string;
  readonly gdb: string;
  readonly windbg: string;
  readonly frida: string;
  readonly scylla: readonly string[];
  readonly notes: readonly string[];
}

const hex = (value: number): string => toHex(value, 16);

export const emitScripts = (input: EmitInput): ScriptBundle => {
  const { image, oep, iat, anti, packer } = input;
  const moduleBase = image.imageBase;
  const entry = image.entryPointVa;
  const oepVa = oep.best?.va ?? null;
  const tlsVas = anti.tlsCallbacks.map((callback) => callback.va);

  const x64dbg: string[] = [
    `// ${image.source.path ?? "<sample>"} · ${packer.primaryFamily ?? "unknown"} · ${packer.verdict}`,
    "// 用法：x64dbg → 文件 → 载入脚本（或在命令栏逐条执行）",
    "// 说明：以下地址使用文件声明的 ImageBase；若开启 ASLR，先 `bp <模块名>:<RVA>` 或手工修正基址",
    "",
    "// --- 1. TLS 回调先下断（早于 EP 执行）---",
    ...tlsVas.map((va) => `bp ${hex(va)}`),
    "",
    "// --- 2. 入口与候选 OEP ---",
    `bp ${hex(entry)}`,
    ...opepCandidates(oep).map((candidate) => `bp ${hex(candidate.va)}   // ${candidate.origin} 得分 ${candidate.score}`),
    "",
    "// --- 3. 间接转移（寄存器/内存跳转，命中后读目标）---",
    ...opepIndirect(oep).map((transfer) => `bp ${hex(transfer.va)}   // ${transfer.note}`),
    "",
    "// --- 4. 反调试热点（命中后决定 patch 或 hook）---",
    ...anti.findings
      .filter((finding) => finding.va !== null && (finding.severity === "high" || finding.category === "tls"))
      .slice(0, 12)
      .map((finding) => `bp ${hex(finding.va ?? 0)}   // ${finding.title}`),
    "",
    "// --- 5. 到 OEP 后 dump ---",
    oepVa === null
      ? "// 未得到静态 OEP 候选：改用 ESP 定律 / 内存写断点，人工定位后再 dump"
      : `// 命中 ${hex(oepVa)} 后执行：`,
    oepVa === null ? "" : `// dump ${hex(moduleBase)}, "dump_${(image.source.sha256 ?? "").slice(0, 8)}.bin"`,
    oepVa === null ? "" : "// 或用 Scylla 插件：右键 → Scylla → IAT Autosearch → Get Imports → Fix Dump",
    "",
    "// --- 6. ESP 定律（若存在 pushad）---",
    oep.espLaw.applicable ? "// 在 pushad 之后执行：r esp → hr <esp值> → F9" : "// 无 pushad：跳过",
    "",
    "ret",
  ];

  const gdb: string[] = [
    `# ${image.source.path ?? "<sample>"} — gdb/lldb 命令序列`,
    "# 载入：gdb -q <binary>（Windows 下用 gdb 需匹配架构）",
    ...tlsVas.map((va, index) => `b *${hex(va)}   # tls-callback-${index}`),
    `b *${hex(entry)}   # entry point`,
    ...opepCandidates(oep).map((candidate) => `b *${hex(candidate.va)}   # oep ${candidate.origin} score=${candidate.score}`),
    oep.espLaw.applicable ? "run\n# 命中 pushad 后：watch *(unsigned long*)$rsp" : "run",
    "# dump：dump binary memory dump.bin <start> <end>",
  ];

  const windbg: string[] = [
    `* ${image.source.path ?? "<sample>"} — WinDbg 命令序列`,
    ...tlsVas.map((va) => `bp ${hex(va)}`),
    `bp ${hex(entry)}`,
    ...opepCandidates(oep).map((candidate) => `bp ${hex(candidate.va)}`),
    oep.espLaw.applicable ? "g\n* 命中后：ba r 1 @esp" : "g",
    `* dump：.writemem dump_${(image.source.sha256 ?? "").slice(0, 8)}.bin ${hex(moduleBase)} L?${toHex(image.sizeOfImage)}`,
  ];

  const frida = buildFridaScript(input);
  const scylla = [
    iat.tooling.scyllaCommand,
    ...iat.tooling.notes.map((note) => `# ${note}`),
  ];

  return {
    x64dbg: x64dbg.join("\n"),
    gdb: gdb.join("\n"),
    windbg: windbg.join("\n"),
    frida,
    scylla,
    notes: [
      "脚本中的地址是文件声明地址；ASLR 下用 模块基址 + RVA 计算真实地址",
      "反调试补丁建议先在副本上验证，再对目标落地",
      "运行时 hook 脚本（frida.js）与静态结论互补：静态负责定位，运行期负责绕过与取内存",
    ],
  };
};

const opepCandidates = (oep: OepHuntResult): readonly { va: number; origin: string; score: number }[] =>
  oep.candidates.slice(0, 5).map((candidate) => ({
    va: candidate.va,
    origin: candidate.origin,
    score: candidate.score,
  }));

const opepIndirect = (oep: OepHuntResult): readonly { va: number; note: string }[] =>
  oep.indirectTransfers
    .filter((transfer) => transfer.va !== null)
    .slice(0, 4)
    .map((transfer) => ({ va: transfer.va ?? 0, note: transfer.note }));

const buildFridaScript = (input: EmitInput): string => {
  const { image, anti, oep } = input;
  const moduleBase = image.imageBase;
  const sizeOfImage = image.sizeOfImage;
  const hooks = anti.hookTargets.slice(0, 24);
  const apiList = JSON.stringify([...new Set(hooks.map((hook) => hook.api))]);

  const lines: string[] = [];
  lines.push("// 运行时镜像导出 + 反调试绕过（Frida）");
  lines.push("// 用法：frida -l this.js -f <target.exe>  或  frida -l this.js <pid>");
  lines.push("'use strict';");
  lines.push("");
  lines.push("const MODULE_BASE = ptr('" + hex(moduleBase) + "');");
  lines.push("const IMAGE_SIZE = " + String(sizeOfImage) + ";");
  lines.push("const OUT_DIR = './dump';");
  lines.push("const log = (m) => console.log('[+] ' + m);");
  lines.push("");
  lines.push("function ensureDir() {");
  lines.push("  try { new File(OUT_DIR + '/.keep', 'wb').write(''); } catch (e) {}");
  lines.push("}");
  lines.push("");
  lines.push("function writeFile(path, bytes) {");
  lines.push("  const f = new File(path, 'wb');");
  lines.push("  f.write(bytes);");
  lines.push("  f.flush();");
  lines.push("  f.close();");
  lines.push("  log('wrote ' + path + ' (' + bytes.byteLength + ' bytes)');");
  lines.push("}");
  lines.push("");
  lines.push("// 取 PEB 指针（BeingDebugged / NtGlobalFlag 修补用）");
  lines.push("function pebPointer() {");
  lines.push("  try {");
  lines.push("    const ntdll = Process.findModuleByName('ntdll.dll');");
  lines.push("    if (!ntdll) return null;");
  lines.push("    const addr = ntdll.findExportByName('NtCurrentTeb');");
  lines.push("    if (addr === null) return null;");
  lines.push("    const fn = new NativeFunction(addr, 'pointer', []);");
  lines.push("    const teb = fn();");
  lines.push("    return teb.add(Process.pointerSize === 8 ? 0x60 : 0x30).readPointer();");
  lines.push("  } catch (e) { return null; }");
  lines.push("}");
  lines.push("");
  lines.push("function patchPeb() {");
  lines.push("  const peb = pebPointer();");
  lines.push("  if (peb === null) { log('PEB 指针不可得，跳过 PEB 修补（改用 API hook）'); return; }");
  lines.push("  try {");
  lines.push("    log('PEB @ ' + peb);");
  lines.push("    peb.add(0x02).writeU8(0);            // BeingDebugged");
  lines.push("    if (Process.pointerSize === 8) peb.add(0xBC).writeU32(0); // NtGlobalFlag (x64)");
  lines.push("    else peb.add(0x68).writeU32(0);      // NtGlobalFlag (x86)");
  lines.push("    const heap = peb.add(Process.pointerSize === 8 ? 0x30 : 0x18).readPointer();");
  lines.push("    if (!heap.isNull()) {");
  lines.push("      heap.add(Process.pointerSize === 8 ? 0x70 : 0x0C).writeU32(2); // Flags: 去掉 debug heap");
  lines.push("    }");
  lines.push("    log('PEB 已修补（BeingDebugged/NtGlobalFlag/Heap.Flags）');");
  lines.push("  } catch (e) { log('PEB 修补失败: ' + e.message); }");
  lines.push("}");
  lines.push("");
  lines.push("// 模块镜像 dump（按 SizeOfImage 逐区读取，保留原始布局）");
  lines.push("function dumpModule(tag) {");
  lines.push("  ensureDir();");
  lines.push("  const path = OUT_DIR + '/dump_' + (tag || 'image') + '_' + MODULE_BASE.toString(16) + '.bin';");
  lines.push("  const total = IMAGE_SIZE;");
  lines.push("  const buf = Memory.alloc(total);");
  lines.push("  let copied = 0;");
  lines.push("  Process.enumerateRanges('r--').forEach((range) => {");
  lines.push("    const start = range.base;");
  lines.push("    const end = range.base.add(range.size);");
  lines.push("    const modEnd = MODULE_BASE.add(total);");
  lines.push("    if (end.compare(MODULE_BASE) <= 0 || start.compare(modEnd) >= 0) return;");
  lines.push("    const from = start.compare(MODULE_BASE) < 0 ? MODULE_BASE : start;");
  lines.push("    const to = end.compare(modEnd) > 0 ? modEnd : end;");
  lines.push("    const len = to.sub(from).toInt32();");
  lines.push("    try {");
  lines.push("      Memory.copy(buf.add(from.sub(MODULE_BASE).toInt32()), from, len);");
  lines.push("      copied += len;");
  lines.push("    } catch (e) { log('range 读取失败 ' + from + ': ' + e.message); }");
  lines.push("  });");
  lines.push("  writeFile(path, buf.readByteArray(total));");
  lines.push("  log('dump 覆盖 ' + copied + '/' + total + ' 字节');");
  lines.push("}");
  lines.push("");
  lines.push("// 反调试 API 覆盖");
  lines.push("const API_LIST = " + apiList + ";");
  lines.push("function hookApi(name) {");
  lines.push("  let addr = null;");
  lines.push("  ['kernel32.dll', 'kernelbase.dll', 'ntdll.dll'].forEach((mod) => {");
  lines.push("    if (addr !== null) return;");
  lines.push("    const m = Process.findModuleByName(mod);");
  lines.push("    if (!m) return;");
  lines.push("    addr = m.findExportByName(name);");
  lines.push("  });");
  lines.push("  if (addr === null) return;");
  lines.push("  Interceptor.attach(addr, {");
  lines.push("    onEnter(args) { this.name = name; },");
  lines.push("    onLeave(retval) {");
  lines.push("      const lower = this.name.toLowerCase();");
  lines.push("      if (lower === 'isdebuggerpresent') { retval.replace(0); }");
  lines.push("      else if (lower === 'checkremotedebuggerpresent') { retval.replace(1); }");
  lines.push("      else if (lower.indexOf('ntqueryinformationprocess') >= 0) { retval.replace(0); }");
  lines.push("      else if (lower === 'outputdebugstringa' || lower === 'outputdebugstringw') { retval.replace(0); }");
  lines.push("      else if (lower.indexOf('gettickcount') === 0 || lower === 'queryperformancecounter') { retval.replace(1); }");
  lines.push("      log('hit ' + this.name + ' -> ' + retval);");
  lines.push("    }");
  lines.push("  });");
  lines.push("  log('hooked ' + name + ' @ ' + addr);");
  lines.push("}");
  lines.push("");
  lines.push("// RWX 转换监听：解压完成的直接信号，同时落盘当时的镜像");
  lines.push("function watchProtect() {");
  lines.push("  const names = ['VirtualProtect', 'NtProtectVirtualMemory', 'VirtualAlloc', 'NtAllocateVirtualMemory'];");
  lines.push("  names.forEach((name) => {");
  lines.push("    let addr = null;");
  lines.push("    ['kernel32.dll', 'kernelbase.dll', 'ntdll.dll'].forEach((mod) => {");
  lines.push("      if (addr !== null) return;");
  lines.push("      const m = Process.findModuleByName(mod);");
  lines.push("      if (m) addr = m.findExportByName(name);");
  lines.push("    });");
  lines.push("    if (addr === null) return;");
  lines.push("    Interceptor.attach(addr, {");
  lines.push("      onEnter(args) {");
  lines.push("        const protect = name.indexOf('Protect') >= 0 ? args[2].toInt32() : args[2].toInt32();");
  lines.push("        const isRwx = (protect & 0x40) !== 0 || (protect & 0x80) !== 0;");
  lines.push("        if (!isRwx) return;");
  lines.push("        log(name + ' rwx pending @ ' + args[0]);");
  lines.push("        setTimeout(() => { try { dumpModule('rwx'); } catch (e) { log('rwx dump 失败: ' + e.message); } }, 0);");
  lines.push("      }");
  lines.push("    });");
  lines.push("  });");
  lines.push("}");
  lines.push("");
  lines.push("// OEP 命中即 dump（静态候选地址）");
  lines.push("function watchOep() {");
  const oepVa = oep.best?.va ?? null;
  if (oepVa === null) {
    lines.push("  log('无静态 OEP 候选：仅依赖 RWX 监听');");
  } else {
    lines.push("  try {");
    lines.push("    Interceptor.attach(ptr('" + hex(oepVa) + "'), { onEnter() { log('OEP hit'); dumpModule('oep'); } });");
    lines.push("    log('OEP watch @ " + hex(oepVa) + "');");
    lines.push("  } catch (e) { log('OEP watch 失败: ' + e.message); }");
  }
  lines.push("}");
  lines.push("");
  lines.push("setImmediate(() => {");
  lines.push("  log('module base ' + MODULE_BASE + ' size ' + IMAGE_SIZE);");
  lines.push("  patchPeb();");
  lines.push("  API_LIST.forEach(hookApi);");
  lines.push("  watchProtect();");
  lines.push("  watchOep();");
  lines.push("});");
  lines.push("");
  return lines.join("\n");
};
