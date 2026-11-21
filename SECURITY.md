# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.4.x | ✅ |
| < 1.4 | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for anything that could be exploited.

Email **lingbol088@gmail.com** with:

1. the version (`lbi version`) and platform;
2. the smallest input that reproduces the problem (a hex dump or a generated fixture is fine — **never send live malware**);
3. the observed behaviour and the expected one;
4. whether the bug is reachable from a default CLI/MCP invocation.

You can expect an acknowledgement within 5 business days and a fix or mitigation plan within 30 days for confirmed issues.

## Scope

In scope:

- parser crashes, unbounded memory/CPU growth, or hangs on crafted PE input (DoS against the analyzing host);
- path traversal or file writes outside the requested output path;
- MCP protocol bugs that could cause a host to execute unintended actions;
- checksum/limits logic that silently mis-reports results.

Out of scope:

- heuristic detection misses ("it did not identify my custom packer") — open a regular issue instead;
- anything requiring the tool to execute a sample (it never does);
- vulnerabilities in third-party decompilers/debuggers you run afterwards.

## Disclosure

Once a fix is released, we publish a short advisory in `CHANGELOG.md` and credit the reporter unless asked otherwise.
