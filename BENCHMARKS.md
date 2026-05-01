# Benchmarks

Two layers of measurement.

## In-repo regression baseline

`tests/cves/CVE-*/` — synthetic Spring Boot modules covering CVE-2017-8046,
CVE-2018-1270, CVE-2022-22947, CVE-2022-22963, CVE-2022-22965. Each has a
compile-only `pom.xml`, vulnerable source, and `EXPECTED.md` listing the
rule ids and lines that must fire.

Run:

```bash
for d in tests/cves/CVE-*; do semgrep scan --config semgrep/ "$d"; done
```

CI (`.github/workflows/validate.yml`) runs this on every PR with `--error`,
so a regression breaks the build.

## External corpus benchmark

Real-world Spring projects (clean apps, vulhub PoCs, OWASP WebGoat, eugenp
tutorials, spring-petclinic-ms) live outside this repo at
`spring-bench/bench/` (tooling at `bench/run_all.sh`). Last run:
**2026-04-30**. Output is in `bench/artifacts/`.

TL;DR coverage from that run, after the Defect 1–6 fixes applied here.
`(src-only)` means a Java source-bearing fixture exists somewhere in the
corpus and is detected; `✗` means no source fixture exists yet for that
family or no rule fires; `partial` means at least one engine reports a
finding but coverage is incomplete.

| Family | Local (this rule pack) |
|---|---|
| SpEL injection | (src-only) ✓ via tests/cves |
| Mass assignment / Spring4Shell | ✓ (PoC + tests/cves) |
| SSRF | (src-only) ✓ |
| Open redirect | ✗ (no source fixture) |
| Path traversal | (src-only) ✓ |
| Insecure deserialization | (src-only) ✓ |
| Authorization bypass | (src-only) ✓ |
| JNDI | (src-only) ✓ |
| XXE | (src-only) ✓ |
| SSTI | (src-only) ✓ |
| CSRF | (src-only) ✓ |
| SQL/JPQL injection | (src-only) ✓ |
| CORS | (src-only) ✓ |
| Cookies | (src-only) ✓ |
| Spring Cloud Function | (src-only) ✓ via tests/cves |
| Spring Cloud Gateway | (src-only) ✓ via tests/cves |
| STOMP / WebSocket | partial (StandardEvaluationContext only — STOMP source family not yet in SpEL taint sources) |
| RCE (Runtime.exec) | ✗ (no source fixture) |
| URI host validation | (src-only) ✓ |

Don't copy this into a marketing page. The "(src-only)" cases mean we know
the rule fires on some shape of the bug, not that we've measured precision
or recall on a representative codebase. For end-to-end recall/precision
against arbitrary Spring projects, run the external bench and look at
`artifacts/coverage.json` plus the per-fixture logs in `logs/`.
