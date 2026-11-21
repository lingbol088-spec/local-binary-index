## What changed

<!-- one paragraph, plain language -->

## Why

<!-- the analysis question this answers, or the bug it fixes -->

## Evidence

- [ ] Added or extended a generated fixture that reproduces the case
- [ ] Added/extended a unit test asserting the new behaviour
- [ ] `npm test` passes locally
- [ ] `CHANGELOG.md` updated (Unreleased)

## Checklist

- [ ] Engine remains read-only (no execution / no network)
- [ ] No new runtime dependencies
- [ ] Loops over file data are bounded and degrade to "partial facts + limitation"
- [ ] Public output changes are documented in `docs/TOOLS.md`