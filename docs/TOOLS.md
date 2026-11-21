# Tools reference

All tools are exposed by `bin/lbi-mcp.mjs` over MCP stdio, and mirrored by CLI subcommands.
Inputs are JSON objects; outputs are JSON text content (MCP) or files (CLI).

Common conventions:

- `path` is an **absolute or working-directory-relative** local file path. The server never fetches URLs.
- Every result includes `coverage` / `limitations` where the analysis could not be complete.
- Addresses are `rva` (image-relative) and `va` (image base + rva). `imageBase` is reported once per result.

---

## `inspect_protection_profile`

Packer / protector / virtualizer / obfuscator / installer / framework identification.

**Input**

| field | type | required | notes |
|---|---|---|---|
| `path` | string | ✅ | local PE file |

**Output (excerpt)**

```jsonc
{
  "verdict": "packed",              // clean | packed | protected | obfuscated | framework | installer
  "confidence": 1,
  "primary_family": "UPX",
  "families": [
    { "id": "upx", "family": "UPX", "category": "packer", "difficulty": "trivial",
      "confidence": 1,
      "signals": [
        { "kind": "section-name", "detail": "区段名精确命中 UPX0", "rva": 8192, "weight": 60 },
        { "kind": "byte-pattern", "detail": "upx2/3-entry @ 0x00000A00 → 60 BE 00 10 40 00 8D BE", "fileOffset": 2560, "weight": 70 }
      ],
      "strategy": ["upx -d <input> -o <output>", "..."] }
  ],
  "generic_signals": [ { "kind": "structural", "detail": "RWX 区段: UPX1", "weight": 14 } ],
  "anomalies": [ { "id": "virtual-only-section", "severity": "high", "detail": "..." } ],
  "limitations": ["..."]
}
```

Signal kinds: `section-name`, `section-prefix`, `ascii-marker`, `byte-pattern`, `overlay-marker`, `structural`.

---

## `inspect_entry_transfer`

OEP candidates from the entry stub, plus runtime breakpoint plans.

**Input**

| field | type | required | notes |
|---|---|---|---|
| `path` | string | ✅ | local PE file |
| `include_internal_jumps` | boolean | ❌ | also report jumps that stay inside the stub section |
| `max_instructions` | number | ❌ | stub decode budget (default 20000) |

**Output (excerpt)**

```jsonc
{
  "entry": { "rva": 16384, "va": 4210688, "sectionName": "UPX1", "entropy": 7.82 },
  "stub":  { "decodedInstructions": 436, "stoppedReason": "section-end", "pushadOffset": 2560, "popadOffset": null },
  "candidates": [
    { "rva": 4096, "va": 4198400, "origin": "push-ret", "score": 100,
      "sectionName": ".text", "evidence": ["push 0x00401000 ; ret（ret @ 0x00000A1E）"] }
  ],
  "espLaw": { "applicable": true, "reason": "...", "commands": ["x64dbg: r esp → hr <esp> → F9"] },
  "breakpoints": [ { "kind": "oep-candidate", "va": 4198400, "x64dbg": "bp 0x401000", "gdb": "b *0x401000", "windbg": "bp 0x401000" } ]
}
```

Scoring: cross-section transfer, executable target, lower entropy than the stub, alignment, and origin weight. `internal-jmp` candidates score low on purpose — they are usually the unpacking loop.

---

## `inspect_import_rebuild_plan`

Where the import table is, what survived, and how to rebuild it.

**Input**

| field | type | required |
|---|---|---|
| `path` | string | ✅ |

**Output (excerpt)**

```jsonc
{
  "current": { "moduleCount": 1, "functionCount": 3, "ordinalOnlyCount": 0,
               "iatRva": 20992, "iatSection": ".idata", "importSection": ".idata",
               "iatDiverseFromImportSection": false, "usedSlotRange": { "first": 5248, "last": 5250 } },
  "descriptorCandidates": [
    { "arrayRva": 21760, "moduleNames": ["USER32.dll", "GDI32.dll"], "terminated": true, "score": 66,
      "note": "2 个模块描述符（有 0 结尾） @ 0x5500" }
  ],
  "blueprint": [ { "dll": "KERNEL32.dll", "functionCount": 3, "slots": [ { "name": "IsDebuggerPresent", "iatVa": 4210688 } ] } ],
  "rebuildSteps": ["1) 在 OEP 断点命中、且目标区段已解压后再 dump", "..."],
  "tooling": { "scyllaCommand": "Scylla.exe -a -p <PID> -o <OUT> --iat 0x5200 --oep 0x4000" }
}
```

`descriptorCandidates` are **unused** `IMAGE_IMPORT_DESCRIPTOR` arrays still present in the file — the cheapest path to a trustworthy import table after dumping.

---

## `inspect_anti_analysis`

Anti-debug / anti-VM / timing / integrity checks, TLS callbacks, hook targets, patch bytes.

**Input**

| field | type | required |
|---|---|---|
| `path` | string | ✅ |

**Output (excerpt)**

```jsonc
{
  "findings": [
    { "id": "int2d", "category": "anti-debug", "severity": "high",
      "title": "INT 2D 反调试（内核调试器异常）",
      "rva": 16400, "va": 4210704, "fileOffset": 2576, "bytes": "CD 2D",
      "patch": { "strategy": "用 NOP 覆盖 2 字节", "patchBytes": "90 90", "fileOffset": 2576 },
      "runtimeBypass": "把 CD 2D 替换为 90 90" }
  ],
  "hookTargets": [ { "api": "IsDebuggerPresent", "dll": "KERNEL32.dll", "iatVa": 4210688,
                     "category": "anti-debug", "suggestedBypass": "返回 0（FALSE）" } ],
  "tlsCallbacks": [ { "rva": 4096, "va": 4198400 } ],
  "score": 54
}
```

`patch.patchBytes` is only emitted where a fixed-width NOP replacement is safe. PEB / NtGlobalFlag / RDTSC have **no** static patch — they carry `runtimeBypass` instructions instead.

---

## `inspect_managed_protection`

.NET structure and obfuscation fingerprints.

**Input**: `{ "path": string }`

**Output (excerpt)**

```jsonc
{
  "isManaged": true,
  "runtimeVersion": "v1.1",
  "metadataVersion": "v4.0.30319",
  "streams": [ { "name": "#~", "offset": 0, "size": 1568784 }, { "name": "#Strings", "offset": 0, "size": 436224 } ],
  "tableRowCounts": { "TypeDef": 3356, "MethodDef": 29257, "Field": 14717, "MemberRef": 3429 },
  "obfuscatorMarkers": [ { "family": "ConfuserEx", "marker": "ConfusedBy", "stream": "#Strings", "streamOffset": 12345 } ],
  "indicators": ["#Strings 中 31.2% 标识符含非 ASCII 字符：重命名型混淆"],
  "steps": ["1) 静态看结构 …", "2) de4dot -f <file> …"]
}
```

---

## `repair_image_dump`

Turn a memory image into a parseable file.

**Input**

| field | type | required | notes |
|---|---|---|---|
| `path` | string | ✅ | dump to repair |
| `output_path` | string | ❌ | write the repaired file |
| `force_memory_layout` | boolean | ❌ | re-layout even if auto-detection says "already a file" |

**Output (excerpt)**

```jsonc
{
  "ok": true, "memory_image": true,
  "original_size": 24576, "repaired_size": 5120,
  "sha256_before": "…", "sha256_after": "…",
  "sections": [ { "name": "UPX1", "virtual_address": 16384, "new_pointer_to_raw_data": 2560, "new_size_of_raw_data": 1024 } ],
  "patched_fields": [ { "field": "SizeOfImage", "before": 24576, "after": 24576 },
                      { "field": "CheckSum", "before": 0, "after": 2491013380 } ],
  "warnings": []
}
```

Post-repair self-check re-parses the output and verifies the entry point lands in an executable section.

---

## `emit_recovery_scripts`

Write a ready-to-run toolset.

**Input**

| field | type | required |
|---|---|---|
| `path` | string | ✅ |
| `out_dir` | string | ❌ (default `./scripts-out`) |

**Output**: `{ "written": ["…/recover.x64dbg.txt", "…/recover.frida.js", …], "report": "…/report.md" }`

The Frida script contains PEB patching (`BeingDebugged`, `NtGlobalFlag`, heap flags), API interception for the detected hook targets, an RWX-transition watcher that dumps on first exec-write, and an OEP-hit dump hook.

---

## `inspect_binary_report`

Everything above, in one call.

**Input**

| field | type | required | notes |
|---|---|---|---|
| `path` | string | ✅ | |
| `out_dir` | string | ❌ | write `report.md`, `analysis.json`, `scripts/` |
| `format` | `"markdown"` \| `"json"` | ❌ | default `markdown` |

Reports are rendered in Chinese by default (the engine targets Chinese-language reverse-engineering workflows); JSON keys are English everywhere, so downstream tooling is language-neutral.

---

## CLI mapping

| Tool | CLI |
|---|---|
| `inspect_protection_profile` | `lbi zxwn profile <file> [--json]` |
| `inspect_entry_transfer` | `lbi zxwn transfer <file> [--json] [--internal]` |
| `inspect_import_rebuild_plan` | `lbi zxwn imports <file> [--json]` |
| `inspect_anti_analysis` | `lbi zxwn anti <file> [--json]` |
| `inspect_managed_protection` | `lbi zxwn managed <file> [--json]` |
| `repair_image_dump` | `lbi zxwn repair-dump <dump> [--out <file>]` |
| `emit_recovery_scripts` | `lbi zxwn scripts <file> --out <dir>` |
| `inspect_binary_report` | `lbi zxwn analyze <file> [--json] [--out <dir>]` |

Byte patching from the CLI:

```bash
lbi zxwn patch target.exe --patches '[{"fileOffset":2576,"bytes":"90 90","reason":"nop int2d"}]' --out patched.exe
```

Bounds-checked, verified by read-back, and rejected patches are reported per item.
