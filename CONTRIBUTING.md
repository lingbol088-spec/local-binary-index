# Contributing

Thanks for taking the time to contribute. This project stays useful only if its conclusions stay checkable, so the bar is: **every behaviour change ships with a fixture that reproduces it.**

## Development setup

```bash
git clone https://github.com/lingbol088-spec/local-binary-index.git
cd local-binary-index
npm ci
npm test
```

`npm test` runs `tsc` → generates synthetic fixtures → executes the unit suite (`node --test`). Nothing else is required; there is no database, no service, and no network access in the test path.

## Repository layout

```
src/
  pe/peFile.ts        PE32/PE32+ parser (headers, sections, imports, exports, TLS, resources, Rich, overlay)
  packer/             signature table + scoring
  oep/x86len.ts       instruction-length decoder (x86 / x86-64)
  oep/hunt.ts         stub walk, OEP candidates, ESP law, breakpoints
  iat/plan.ts         import census, residual descriptor scan, rebuild plan
  antidebug/scan.ts   anti-debug / anti-VM patterns, patches, hook targets
  dotnet/managed.ts   CLR + metadata reader
  runtime/            dump repair, script emission
  report/markdown.ts  report renderer
  mcp/server.ts       MCP stdio server
  cli.ts              CLI
scripts/make-fixtures.mjs   deterministic synthetic samples
test/analysis.test.ts       unit suite
```

## Ground rules

- **No execution.** Never add code that loads, maps executable, or runs the analyzed file. Reviewers will reject it.
- **No network.** No telemetry, no signature downloads, no "call home" checks.
- **No new runtime dependencies.** The package ships with zero; keep it that way unless there is no alternative.
- **Bounded loops.** Any loop over attacker-controlled data needs an explicit cap and must degrade to "partial facts + limitation" instead of throwing.
- **Evidence with results.** A new detector reports the section/marker/offset that triggered it. A verdict without evidence will not be merged.
- **Honest limits.** Unsupported formats and unresolved indirection are reported as unknown, not guessed.

## Adding a detection signature

1. Add the entry to `src/packer/signatures.ts` (id, family, category, difficulty, markers/patterns, strategy steps).
2. Extend `scripts/make-fixtures.mjs` so a fixture actually carries the marker.
3. Add a test asserting the family and the specific signal kind.
4. Update `docs/TOOLS.md` if the public output shape changes.

## Running checks locally

```bash
npm run build        # tsc
npm test             # build + fixtures + unit tests
npm run demo         # end-to-end run on the synthetic UPX-shaped fixture
npm pack --dry-run   # inspect what would be published
```

## Pull requests

- One logical change per PR; keep diffs reviewable.
- Update `CHANGELOG.md` under an "Unreleased" heading.
- If you change TOML/JSON output or CLI flags, note the migration in the PR description.
- CI must be green on Node 20 and 22.

## Commit style

`type(scope): summary` — e.g. `fix(oep): stop stub walk at section end`, `feat(iat): scan residual descriptors`.

## Reporting bugs

Use the issue template and include:

- `lbi version`, OS, Node version;
- the command/tool call, expected vs actual;
- for parser bugs, a **generated** fixture or a minimal hex description — never attach live malware.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
