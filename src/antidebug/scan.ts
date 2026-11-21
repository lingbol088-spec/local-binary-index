/**
 * 反调试 / 反虚拟机 / 完整性校验 扫描器。
 *
 * 输出三类可操作结果：
 *   1. 字节级特征 → 可直接 NOP 的补丁（给 fileOffset + patchBytes）
 *   2. IAT 级 hook 目标 → 运行期劫持（给 iatVa + 建议返回值）
 *   3. 策略级发现 → 说明为什么静态补丁不够，需要运行时处理
 */
import type { PeImage } from "../pe/peFile.js";
import { makeRvaResolver } from "../pe/peFile.js";
import { hexBytes, indexOfAll, toHex } from "../util/bytes.js";
import { compilePattern, scanPattern } from "../packer/detect.js";

export type AntiAnalysisCategory = "anti-debug" | "anti-vm" | "timing" | "integrity" | "tls" | "process-guard";

export interface AntiAnalysisFinding {
  readonly id: string;
  readonly category: AntiAnalysisCategory;
  readonly severity: "high" | "medium" | "low" | "info";
  readonly title: string;
  readonly detail: string;
  readonly rva: number | null;
  readonly va: number | null;
  readonly fileOffset: number | null;
  readonly bytes: string | null;
  readonly patch: { readonly strategy: string; readonly patchBytes: string | null; readonly fileOffset: number | null } | null;
  readonly runtimeBypass: string | null;
}

export interface HookTarget {
  readonly api: string;
  readonly dll: string;
  readonly iatVa: number;
  readonly iatRva: number;
  readonly category: AntiAnalysisCategory;
  readonly suggestedBypass: string;
}

export interface AntiAnalysisResult {
  readonly findings: readonly AntiAnalysisFinding[];
  readonly hookTargets: readonly HookTarget[];
  readonly tlsCallbacks: readonly { readonly rva: number; readonly va: number }[];
  readonly score: number;
  readonly notes: readonly string[];
  readonly limitations: readonly string[];
}

interface ByteSignature {
  readonly id: string;
  readonly category: AntiAnalysisCategory;
  readonly severity: "high" | "medium" | "low" | "info";
  readonly title: string;
  readonly detail: string;
  readonly pattern: string;
  readonly nopPatch: boolean;
  readonly runtimeBypass: string | null;
  readonly maxHits?: number;
}

const BYTE_SIGNATURES: readonly ByteSignature[] = [
  {
    id: "peb-beingdebugged-x86",
    category: "anti-debug",
    severity: "high",
    title: "PEB.BeingDebugged 读取（x86 fs:[0x30]）",
    detail: "读取 PEB 的 BeingDebugged 字节（偏移 +2）判断是否被调试；常见于 Themida/VMProtect 与自研壳。",
    pattern: "64 A1 30 00 00 00",
    nopPatch: false,
    maxHits: 8,
    runtimeBypass: "hook ntdll!NtQueryInformationProcess + 在 PEB 写入前把 BeingDebugged 归零（或直接 patch PEB 内存）",
  },
  {
    id: "peb-beingdebugged-x86-reg",
    category: "anti-debug",
    severity: "high",
    title: "PEB 基址读取（x86 fs:[0x30]，寄存器形式）",
    detail: "通过 fs:[0x30] 装载 PEB 指针，后续通常读取 +0x02 / +0x68 / +0xBC。",
    pattern: "64 8B ?5 30 00 00 00",
    nopPatch: false,
    runtimeBypass: "在 PEB 上做运行时修补（BeingDebugged=0, NtGlobalFlag=0, Heap->Flags=0）",
  },
  {
    id: "peb-gs-x64",
    category: "anti-debug",
    severity: "high",
    title: "PEB 读取（x64 gs:[0x60]）",
    detail: "x64 下 PEB 通过 gs:[0x60] 获取，随后检查 BeingDebugged / NtGlobalFlag。",
    pattern: "65 48 8B 04 25 60 00 00 00",
    nopPatch: false,
    maxHits: 8,
    runtimeBypass: "运行时把 PEB.BeingDebugged 与 NtGlobalFlag 归零，并 hook NtQueryInformationProcess",
  },
  {
    id: "rdtsc-timing",
    category: "timing",
    severity: "medium",
    title: "RDTSC 时间差检测",
    detail: "用 RDTSC 前后差值判断单步/断点造成的时延；壳与授权校验常见。",
    pattern: "0F 31",
    nopPatch: false,
    maxHits: 8,
    runtimeBypass: "hook 时间源（GetTickCount/QueryPerformanceCounter），或在 RDTSC 处返回常量（Frida 侧拦截）",
  },
  {
    id: "int2d",
    category: "anti-debug",
    severity: "high",
    title: "INT 2D 反调试（内核调试器异常）",
    detail: "INT 2D 在调试器下行为与正常执行不同，是老式反调试手法。",
    pattern: "CD 2D",
    nopPatch: true,
    runtimeBypass: "把 CD 2D 替换为 90 90（本工具可直接给出补丁字节）",
  },
  {
    id: "icebp",
    category: "anti-debug",
    severity: "medium",
    title: "ICEBP / INT1 指令",
    detail: "F1 触发单步异常，用异常处理流程探测调试器。",
    pattern: "F1",
    nopPatch: true,
    maxHits: 4,
    runtimeBypass: "替换为 90；若不安全则接管 SEH/VEH 异常处理",
  },
  {
    id: "ud2-trap",
    category: "anti-debug",
    severity: "low",
    title: "UD2 非法指令陷阱",
    detail: "0F 0B 触发 #UD，常与异常处理配合做控制流校验或反调试。",
    pattern: "0F 0B",
    nopPatch: true,
    maxHits: 8,
    runtimeBypass: "替换为 90 90 或接管异常分发",
  },
  {
    id: "cpuid-hypervisor",
    category: "anti-vm",
    severity: "medium",
    title: "CPUID 虚拟机探测",
    detail: "CPUID 用于读取 hypervisor 厂商串（VMwareVMM/VBoxVMM/KVMKVMKVM），或探测虚拟机退出。",
    pattern: "0F A2",
    nopPatch: false,
    maxHits: 8,
    runtimeBypass: "hook cpuid（Frida CpuContext 读写 eax/ebx/ecx/edx），返回裸机结果",
  },
  {
    id: "vmware-backdoor",
    category: "anti-vm",
    severity: "medium",
    title: "VMware 后门端口探测",
    detail: "mov dx,0x5658 + in eax,dx 是 VMware 后门指令，用于确认运行在 VMware 上。",
    pattern: "66 BA 58 56",
    nopPatch: false,
    runtimeBypass: "hook in/out 或直接在非 VMware 环境运行",
  },
];

const API_CATEGORIES: Readonly<Record<string, { category: AntiAnalysisCategory; bypass: string }>> = {
  isdebuggerpresent: { category: "anti-debug", bypass: "返回 0（FALSE）" },
  checkremotedebuggerpresent: { category: "anti-debug", bypass: "输出参数置 0 并返回 TRUE" },
  ntqueryinformationprocess: { category: "anti-debug", bypass: "ProcessDebugPort(7)/ProcessDebugFlags(31)/ProcessDebugObjectHandle(30) 全部伪装" },
  zwqueryinformationprocess: { category: "anti-debug", bypass: "同上（native 版本）" },
  ntsetinformationthread: { category: "anti-debug", bypass: "ThreadHideFromDebugger 调用直接返回成功但不生效" },
  ntqueryobject: { category: "anti-debug", bypass: "DebugObject 类型查询返回 STATUS_INVALID_HANDLE" },
  debugactiveprocess: { category: "anti-debug", bypass: "返回失败" },
  debugbreak: { category: "anti-debug", bypass: "空实现" },
  outputdebugstringa: { category: "anti-debug", bypass: "记录参数后直接返回（OutputDebugString 探测）" },
  outputdebugstringw: { category: "anti-debug", bypass: "同上" },
  setunhandledexceptionfilter: { category: "anti-debug", bypass: "返回原过滤器，阻止壳接管崩溃流程" },
  rtladdvectoredexceptionhandler: { category: "anti-debug", bypass: "记录回调地址，便于定位壳的异常流程" },
  queryperformancecounter: { category: "timing", bypass: "返回单调小步进（模拟真实时间流逝）" },
  gettickcount: { category: "timing", bypass: "返回可控常量或慢速递增" },
  gettickcount64: { category: "timing", bypass: "同上" },
  timegettime: { category: "timing", bypass: "同上" },
  getadaptersinfo: { category: "anti-vm", bypass: "返回伪造 MAC（非 00:0C:29 / 08:00:27 / 00:50:56）" },
  getsystemfirmwaretable: { category: "anti-vm", bypass: "返回失败或伪造 SMBIOS" },
  enumprocesses: { category: "process-guard", bypass: "过滤进程列表（隐藏调试器）" },
  createtoolhelp32snapshot: { category: "process-guard", bypass: "过滤进程/模块快照" },
  process32first: { category: "process-guard", bypass: "过滤调试器进程名" },
  process32next: { category: "process-guard", bypass: "同上" },
  openprocess: { category: "process-guard", bypass: "对调试器 PID 返回失败" },
  readprocessmemory: { category: "process-guard", bypass: "记录目标，阻止读取自身代码段" },
  writeprocessmemory: { category: "process-guard", bypass: "记录目标，阻止自修改" },
  virtualprotect: { category: "process-guard", bypass: "记录 RWX 转换（也是解压完成信号）" },
  virtualalloc: { category: "process-guard", bypass: "记录可执行分配（壳的解压缓冲区）" },
  mapfileandchecksumw: { category: "integrity", bypass: "返回预置校验和" },
  checksummappedfile: { category: "integrity", bypass: "同上" },
  imagegetdigeststream: { category: "integrity", bypass: "返回伪造摘要" },
};

export const scanAntiAnalysis = (image: PeImage, bytes: Uint8Array): AntiAnalysisResult => {
  const resolver = makeRvaResolver(image);
  const findings: AntiAnalysisFinding[] = [];
  const hookTargets: HookTarget[] = [];

  const executableRanges = image.sections
    .filter((section) => section.flags.executable && section.availableRawBytes > 0)
    .map((section) => ({
      section,
      start: section.pointerToRawData,
      end: section.pointerToRawData + section.availableRawBytes,
    }));

  for (const signature of BYTE_SIGNATURES) {
    const compiled = compilePattern(signature.pattern);
    let collected = 0;
    for (const range of executableRanges) {
      const slice = bytes.subarray(range.start, range.end);
      const remaining = (signature.maxHits ?? 16) - collected;
      if (remaining <= 0) break;
      const hits = scanPattern(slice, compiled, remaining);
      for (const hit of hits) {
        const fileOffset = range.start + hit.offset;
        const rva = resolver.offsetToRva(fileOffset);
        const length = compiled.bytes.length;
        findings.push({
          id: signature.id,
          category: signature.category,
          severity: signature.severity,
          title: signature.title,
          detail: `${signature.detail} 命中于 ${range.section.name || `#${range.section.index}`} @ ${toHex(fileOffset)}`,
          rva,
          va: rva === null ? null : image.imageBase + rva,
          fileOffset,
          bytes: hit.bytes,
          patch: signature.nopPatch
            ? {
                strategy: `用 NOP 覆盖 ${length} 字节（90 × ${length}）`,
                patchBytes: Array.from({ length }, () => "90").join(" "),
                fileOffset,
              }
            : { strategy: signature.runtimeBypass ?? "需运行时处理", patchBytes: null, fileOffset },
          runtimeBypass: signature.runtimeBypass,
        });
      }
      collected = findings.filter((finding) => finding.id === signature.id).length;
    }
  }

  // IAT 级 hook 目标
  for (const module of image.imports) {
    const dll = module.name.toLowerCase();
    for (const fn of module.functions) {
      const name = fn.name?.toLowerCase() ?? null;
      if (name === null) continue;
      const entry = API_CATEGORIES[name];
      if (!entry) continue;
      hookTargets.push({
        api: fn.name ?? name,
        dll: module.name,
        iatVa: fn.iatVa,
        iatRva: fn.iatRva,
        category: entry.category,
        suggestedBypass: entry.bypass,
      });
    }
    if (dll.includes("sbiedll") || dll.includes("wine") || dll.includes("dbghelp")) {
      findings.push({
        id: "sandbox-import",
        category: "anti-vm",
        severity: "low",
        title: `导入了环境指纹相关模块 ${module.name}`,
        detail: "沙箱/调试辅助模块被显式引用，说明存在环境探测逻辑。",
        rva: null,
        va: null,
        fileOffset: null,
        bytes: null,
        patch: null,
        runtimeBypass: "按需伪造模块存在性",
      });
    }
  }

  // TLS 回调：壳的反调试常驻于此，先于入口运行
  if (image.tls && image.tls.callbackRvas.length > 0) {
    for (const rva of image.tls.callbackRvas) {
      findings.push({
        id: "tls-callback",
        category: "tls",
        severity: "high",
        title: "TLS 回调（入口点之前执行）",
        detail:
          "TLS 回调在 EP 之前运行，加壳器/保护器常把反调试、解压准备、异常接管放在这里；调试时应先在回调下断。",
        rva,
        va: image.imageBase + rva,
        fileOffset: resolver.rvaToOffset(rva),
        bytes: null,
        patch: null,
        runtimeBypass: `在 ${toHex(image.imageBase + rva, 16)} 下断，或在 TLS 目录里摘掉回调`,
      });
    }
  }

  // 环境指纹字符串
  const environmentStrings = [
    "SbieDll.dll",
    "vmware",
    "VBox",
    "VBOX",
    "VirtualBox",
    "qemu",
    "QEMU",
    "SOFTWARE\\VMware",
    "HARDWARE\\DEVICEMAP\\Scsi",
    "\\\\.\\pipe\\cuckoo",
    "wine_get_unix_file_name",
    "x64dbg",
    "ollydbg",
    "idaq",
    "ida64",
  ];
  for (const marker of environmentStrings) {
    const hits = indexOfAll(bytes, Uint8Array.from(Buffer.from(marker, "latin1")), { limit: 1 });
    const first = hits[0];
    if (first === undefined) continue;
    const rva = resolver.offsetToRva(first);
    findings.push({
      id: "environment-fingerprint",
      category: "anti-vm",
      severity: "low",
      title: `环境指纹字符串 ${JSON.stringify(marker)}`,
      detail: "字符串被硬编码用于识别沙箱/虚拟机/调试器；既可能是检测，也可能是日志。",
      rva,
      va: rva === null ? null : image.imageBase + rva,
      fileOffset: first,
      bytes: null,
      patch: null,
      runtimeBypass: "在对应比较处强制走非虚拟机分支",
    });
  }

  // 计分：同类命中最多 3 条计入，避免单字节特征把分数打满
  const severityWeight = { high: 15, medium: 6, low: 2, info: 0 } as const;
  const perSignature = new Map<string, number>();
  let weighted = 0;
  for (const finding of findings) {
    const used = perSignature.get(finding.id) ?? 0;
    if (used >= 3) continue;
    perSignature.set(finding.id, used + 1);
    weighted += severityWeight[finding.severity];
  }
  const score = Math.min(100, weighted + hookTargets.length * 2);

  const notes: string[] = [];
  if (image.tls?.callbackVas && image.tls.callbackVas.length > 0) {
    notes.push(`TLS 回调 VA: ${image.tls.callbackVas.map((va) => toHex(va, 16)).join(", ")}`);
  }
  if (hookTargets.length > 0) {
    notes.push(
      `IAT hook 目标 ${hookTargets.length} 个：${[...new Set(hookTargets.map((target) => target.api))].slice(0, 12).join(", ")}`,
    );
  }

  return {
    findings,
    hookTargets,
    tlsCallbacks: (image.tls?.callbackRvas ?? []).map((rva) => ({ rva, va: image.imageBase + rva })),
    score,
    notes,
    limitations: [
      "字节特征按模式匹配，代码段里可能有巧合命中的常量（需人工确认上下文）",
      "PEB/NtGlobalFlag 类检测不能靠 NOP 解决，必须运行时修补",
      "未覆盖：硬件断点检测（DR 寄存器）、时间戳签名校验、内核回调",
      "覆盖率为「已扫描可执行区段」，非可执行区段里的数据驱动检测不在其中",
    ],
  };
};

/** 生成可直接执行的补丁清单（只含可安全 NOP 的项）。 */
export const buildPatchList = (
  result: AntiAnalysisResult,
): readonly { readonly fileOffset: number; readonly bytes: string; readonly reason: string }[] =>
  result.findings
    .filter((finding) => finding.patch?.patchBytes && finding.fileOffset !== null)
    .map((finding) => ({
      fileOffset: finding.fileOffset ?? 0,
      bytes: finding.patch?.patchBytes ?? "",
      reason: `${finding.id}: ${finding.title}（${finding.bytes ?? ""}）`,
    }));

export const summarizeAntiAnalysisBytes = (result: AntiAnalysisResult): string =>
  hexBytes(Uint8Array.from(result.findings.flatMap((finding) => (finding.fileOffset === null ? [] : [finding.fileOffset & 0xff]))));
