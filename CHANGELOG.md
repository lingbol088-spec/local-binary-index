# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [1.4.3] - 2026-11-21

### Added
- `status` command (`lbi status`, `tools/status.cmd -Json` in the Windows bundle): three-state machine `ready` / `installed-needs-reload` / `not-deployed` for agent-side decision making.
- MCP `prompts` capability: the `zxwn` prompt returns the capability table for clients that surface prompts as slash commands.
- Process-level guards (`uncaughtException`, `unhandledRejection`) so a tool bug cannot silently kill the stdio server.

### Fixed
- MCP config emitter now writes TOML with double-quoted, backslash-escaped paths. The previous literal-quoted form broke `config.toml` whenever a path contained an apostrophe (`O'Brien`), which made the host refuse to start.
- Windows `.cmd` launchers rewritten without parenthesized blocks: a directory name containing a comma no longer truncates the path (`'D:\...\zx' is not recognized`).
- `.cmd` files normalised to CRLF + ASCII; `-NoPause` now also suppresses the pause on failure paths.
- `status`/`reload` child-process detection: single-element arrays returned from functions unroll into a scalar, so `.Count` was `$null` and the check always reported "not connected".

## [1.4.2] - 2026-11-20

### Added
- `.NET` metadata reader: CLR header, stream table, `#~` row counts, obfuscator fingerprints.
- `repair_image_dump`: section re-layout, header rewrite, PE checksum recompute, post-repair re-parse.
- Script emission for x64dbg, gdb, WinDbg, Scylla and Frida.

### Fixed
- Section names are read as NUL-terminated strings; the previous ASCII pass turned padding into `.`, so `UPX0` never matched.
- `mov r32, imm32` (`0xB8`–`0xBF`) immediate length in the x86 decoder; stub walking desynchronised after the first `mov`.

## [1.4.0] - 2026-11-20

### Added
- Initial public shape: PE parser, packer signatures, OEP hunter with ESP law, IAT rebuild planner, anti-analysis scanner, Markdown/JSON reporting, MCP stdio server, CLI.