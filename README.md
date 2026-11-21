<div align="center">

# local-binary-index

**Offline PE inspection engine that speaks MCP — packer ID, OEP hunting, IAT rebuild, anti-debug patches, .NET fingerprints, dump repair.**

[![npm](https://img.shields.io/badge/node-%E2%89%A520.11-brightgreen)](https://nodejs.org)
[![CI](https://github.com/lingbol088-spec/local-binary-index/actions/workflows/ci.yml/badge.svg)](https://github.com/lingbol088-spec/local-binary-index/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20deps-0-success)](package.json)
[![tests](https://img.shields.io/badge/tests-10%20unit-informational)](test/analysis.test.ts)
[![MCP](https://img.shields.io/badge/MCP-stdio-8A2BE2)](https://modelcontextprotocol.io)
[![PRs](https://img.shields.io/badge/PRs-welcome-orange)](CONTRIBUTING.md)

[English](README.md) · [简体中文](README.zh-CN.md) · [Tools reference](docs/TOOLS.md) · [Disclaimer](DISCLAIMER.md)

</div>

> **Read the [DISCLAIMER](DISCLAIMER.md) before use.** This project is for authorized security research, incident response, and education on binaries **you own or are permitted to analyze**. It does not ship or fetch malware, and it never executes its targets.

---

## What it is

A single-purpose, dependency-free PE analysis core, packaged three ways:

| Surface | What you get |
|---|---|
| **MCP server** (`lbi-mcp`) | 8 tools an agent can call over stdio — works with Codex, Claude Desktop, Cursor, or any MCP client |
| **CLI** (`lbi`) | The same engine from a terminal, JSON or Markdown out |
| **Library** (ESM) | `import { analyzeFile } from "local-binary-index"` |

Everything is static: files are read, parsed, and reasoned about. Nothing is unpacked into memory, nothing is executed, nothing leaves the machine.

```text
$ lbi zxwn analyze samples/packed.exe --out ./out
判定: packed (1)          主家族: UPX
OEP : 0x0000000000401000  (push 0x401000 ; ret, score 100)
IAT : 1 module / 3 functions · residual descriptor @0x00005500 (USER32.dll, GDI32.dll)
反分析: int 2d @0x00000A10 → patch 90 90 · icebp ×4 · TLS callback ×1
written: out/report.md, out/analysis.json, out/scripts/{x64dbg,gdb,windbg,frida,scylla,patches}
```

---

## Why another PE tool

Most "what packer is this" answers are a filename, a section name, and a guess. The useful answer is a *plan*: which family, how confident, where the entry transfer is, where the import table went, which anti-debug checks will bite you, and what to patch or breakpoint first.

`local-binary-index` returns that plan as structured, evidence-linked data — every signal carries its file offset, and every report carries a SHA-256 per section, so a human (or another agent) can re-derive the conclusion instead of trusting it.

**Design rules**

1. **Evidence over verdict** — each match reports the exact section name, marker string, byte pattern, or overlay offset behind it.
2. **No execution, ever** — no emulator, no loader, no `CreateProcess`, no network.
3. **Honest unknowns** — unsupported formats and unresolved indirect jumps are stated, not guessed.
4. **Bounded work** — every loop has a cap; malformed or truncated input returns partial facts plus explicit limitations instead of throwing.

---

## Features

| Area | What it does |
|---|---|
| **Protection profiling** | 25 signature families (UPX, ASPack, PECompact, MPRESS, Themida/WinLicense, VMProtect, Enigma, Armadillo, .NET Reactor, ConfuserEx, KoiVM, PyInstaller, Electron, NSIS, Inno, Go, Rust, …) + structural heuristics (virtual-only sections, RWX, entry in last section, checksum mismatch, IAT moved out of `.idata`, high-entropy sections) |
| **OEP hunting** | Walks the entry stub with a length-accurate x86/x86-64 decoder, finds `push imm32; ret`, cross-section relative jumps, and `popad`-then-jump; scores candidates; emits ESP-law and BND-style breakpoint plans for x64dbg / gdb / WinDbg |
| **Import rebuild planning** | Current module/function map, ordinal-only census, IAT location vs `.idata`, **residual `IMAGE_IMPORT_DESCRIPTOR` array scan**, rebuild steps and Scylla/x64dbg commands |
| **Anti-analysis scan** | PEB (`fs:[0x30]`, `gs:[0x60]`), NtGlobalFlag, `rdtsc`, `int 2d`, `icebp`, `ud2`, CPUID hypervisor probe, VMware backdoor port; TLS callbacks; IAT-level hook targets with suggested return values; **NOP patches with file offsets** |
| **Managed code** | CLR header, metadata streams (`#~`, `#Strings`, `#US`, `#Blob`, `#GUID`), table row counts (TypeDef/MethodDef/Field/MemberRef/AssemblyRef), obfuscator fingerprints, obfuscation-strength indicators |
| **Dump repair** | Memory image → parseable file: section re-layout, `SizeOfRawData`/`PointerToRawData`/`SizeOfImage`/`SizeOfHeaders` rewrite, PE checksum recompute, then self-verification by re-parsing |
| **Script emission** | Ready-to-run x64dbg, gdb, WinDbg, Scylla, and Frida assets (PEB patching, API interception, RWX watch, auto-dump on OEP hit) |
| **Reporting** | Markdown + JSON + per-section evidence chain (E-001 …) |

---

## Quick start

```bash
git clone https://github.com/lingbol088-spec/local-binary-index.git
cd local-binary-index
npm ci
npm test          # builds, generates synthetic fixtures, runs 10 unit tests
```

### Use as an MCP server

**Codex desktop / CLI** (`~/.codex/config.toml`):

```toml
[mcp_servers.local-binary-index]
command = "node"
args = ["/absolute/path/to/local-binary-index/bin/lbi-mcp.mjs"]
startup_timeout_sec = 60

[mcp_servers.local-binary-index.env]
LBI_TOKEN = "zxwn"      # activation token; omit for the inert catalog
```

**Claude Desktop / Cursor / any `mcpServers` JSON:**

```json
{
  "mcpServers": {
    "local-binary-index": {
      "command": "node",
      "args": ["/absolute/path/to/local-binary-index/bin/lbi-mcp.mjs"],
      "env": { "LBI_TOKEN": "zxwn" }
    }
  }
}
```

Then, in a **new** conversation:

```text
you: zxwn
agent: (capability table) … which file do you want analyzed?
you: D:\samples\target.exe — what packer is this and how do I unpack it
```

### Use as a CLI

```bash
npx lbi status
npx lbi zxwn profile  samples/packed.exe
npx lbi zxwn transfer samples/packed.exe
npx lbi zxwn imports  samples/packed.exe
npx lbi zxwn anti     samples/packed.exe
npx lbi zxwn managed  samples/assembly.dll
npx lbi zxwn analyze  samples/packed.exe --out ./out
npx lbi zxwn repair-dump dump.bin --out fixed.exe
```

Every command accepts `--json` (except `analyze`, which writes files) so it drops into pipelines.

---

## The 8 MCP tools

| Tool | Question it answers | Notable output |
|---|---|---|
| `inspect_protection_profile` | What is this, and what does breaking it take? | verdict, family, confidence, per-signal evidence, structural anomalies, strategy list |
| `inspect_entry_transfer` | Where does the original code start? | scored OEP candidates with source instruction, ESP-law plan, breakpoints for 3 debuggers |
| `inspect_import_rebuild_plan` | Where did the import table go? | IAT census, ordinal-only list, residual descriptor arrays, rebuild steps |
| `inspect_anti_analysis` | What will fight the debugger? | findings with file offsets, patch bytes where safe, IAT hook targets + suggested returns, TLS callbacks |
| `inspect_managed_protection` | Is it .NET, and how obfuscated? | CLR runtime, streams, table row counts, obfuscator markers, indicators |
| `repair_image_dump` | Can this memory dump be parsed? | re-laid sections, rewritten headers, recomputed checksum, post-repair self-check |
| `emit_recovery_scripts` | What do I paste into my debugger? | x64dbg / gdb / WinDbg / Scylla / Frida files |
| `inspect_binary_report` | Give me the whole thing. | Markdown + JSON + evidence chain |

Full input/output schemas: **[docs/TOOLS.md](docs/TOOLS.md)**.

---

## Trigger word and activation

The server has two catalogs:

| State | Condition | `tools/list` |
|---|---|---|
| inert | no `LBI_TOKEN`, or the local state file is missing/expired/mismatched | 1 (`index_status`) |
| armed | `LBI_TOKEN=zxwn`, or state file holds `zxwn` and has not expired | 8 |

```bash
lbi zxwn arm --minutes 1440   # arm for 24h (0 = never expires)
lbi zxwn disarm               # drop back to the inert catalog immediately
lbi status                    # show activation + expiry
```

Why: an agent workstation often runs several MCP servers. Keeping a binary-analysis surface inert until it is explicitly armed makes accidental tool use visible and auditable.

---

## How it works

```text
                 ┌──────────────────────────────────────────────────────┐
   file bytes ──▶│ peFile      headers · sections · imports · exports   │
                 │             TLS · resources · debug · Rich · overlay │
                 └───────────────┬──────────────────────────────────────┘
                                 │  PeImage (RVA⇄offset resolver, anomalies)
        ┌────────────────────────┼───────────────────────────┬─────────────────────┐
        ▼                        ▼                           ▼                     ▼
  packer/detect            oep/x86len + hunt            iat/plan            antidebug/scan
  signatures + heuristics  stub walk → candidates       IAT census +        patterns + IAT hooks
  → families, confidence   ESP law + breakpoints        residual descriptors → patches, hook targets
        │                        │                           │                     │
        └────────────┬───────────┴─────────────┬─────────────┴──────────┬──────────┘
                     ▼                         ▼                        ▼
              runtime/scripts           runtime/fixDump            report/markdown
              x64dbg/gdb/windbg         dump → file layout         Markdown + JSON + evidence
              scylla/frida              + checksum recompute
```

Everything is pure computation over `Uint8Array`. The only I/O is reading the target file and (optionally) writing reports/scripts.

---

## What real runs look like

| Target | Result |
|---|---|
| Synthetic UPX-shaped PE32 (5,136 B) | `packed` (1.0) · UPX · OEP `0x401000` score 100 · patches `int 2d @0x00000A10 → 90 90` · residual descriptor `@0x00005500` = USER32.dll, GDI32.dll |
| `notepad.exe` (x64, real Windows binary) | `clean` · 50 modules / 315 imports · 12 anti-analysis findings · 0 structural anomalies |
| `mscorlib.dll` (.NET 4) | CLR `v1.1` · metadata `v4.0.30319` · 31 tables · TypeDef 3,356 / MethodDef 29,257 |
| 24,576 B memory dump | memory→file re-layout · pointers rewritten · checksum recomputed · re-parsed successfully |

Reproduce locally: `npm run fixtures && npm run demo`.

---

## Compatibility

| Item | Support |
|---|---|
| Input formats | PE32 / PE32+ (EXE, DLL, SYS); .NET assemblies |
| Not supported | ELF, Mach-O, 16-bit NE/LE (rejected with an explicit error) |
| Host OS | Windows / macOS / Linux (pure Node) |
| Node | ≥ 20.11 |
| Runtime deps | none |
| MCP transport | stdio |

---

## Safety model

- **Read-only.** The engine opens files, never maps them executable, never spawns them.
- **No network.** No telemetry, no remote lookups, no signature downloads.
- **No samples shipped.** Fixtures are generated locally by `scripts/make-fixtures.mjs` and contain no malicious code.
- **Deterministic.** Same bytes in, same JSON out; every report carries hashes so results can be audited.

---

## Limitations

- Static analysis cannot recover an encrypted packer payload; for those you need a runtime dump (the Frida script gets you there, the analysis does not).
- Single-byte signatures (`F1` icebp) can match by coincidence in random data; hit counts are capped and flagged.
- x86-64 VEX/EVEX decoding is length-approximate; decoding stops at the first invalid byte and reports where.
- IAT rebuild is a plan plus residual-descriptor discovery, not an automated Scylla replacement.
- `.NET` metadata is read structurally; IL is not decompiled here (use a dedicated decompiler on the output).

---

## FAQ

**Does it unpack anything?**
No. It tells you *how* to unpack, and generates the debugger/Frida assets that do the runtime part.

**Why is the catalog inert by default?**
So that a shared workstation does not silently grow a binary-analysis attack surface. Arm it with `zxwn`, optionally with an expiry.

**Can I use it commercially?**
MIT license permits it. Read [DISCLAIMER.md](DISCLAIMER.md) — permitted use is still your responsibility.

**Where do I start with an unknown binary?**
`analyze` → read `protection.verdict` and `entryTransfer.candidates[0]` → follow the emitted x64dbg script.

---

## Roadmap

- [ ] ELF support (packer ID + `.init_array` analysis)
- [ ] Mach-O support
- [ ] Direct Scylla-compatible `.scv` IAT export
- [ ] Optional YARA rule export from detection signals
- [ ] WASM build of the parser core for browser-side triage

---

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please run `npm test` before opening a PR, and keep new detection signatures backed by a reproducible fixture.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Please do not open a public issue for an exploitable parser bug.

## License

[MIT](LICENSE) © 2026 li lingbo

## Disclaimer

This software is provided **as is**, without warranty of any kind. It is intended **only** for lawful analysis of binaries you own or are explicitly authorized to examine (security research, incident response, CTF, malware triage in an isolated lab). Do not use it to circumvent protection on software you do not have rights to, to develop or distribute malware, or in violation of any applicable law. The authors accept no liability for misuse or damage. Full text: **[DISCLAIMER.md](DISCLAIMER.md)**.
