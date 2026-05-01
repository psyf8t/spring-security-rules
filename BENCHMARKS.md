# Benchmarks

Two layers of measurement.

## In-repo regression baseline

`tests/cves/CVE-*/` — five synthetic Spring Boot modules (CVE-2017-8046,
CVE-2018-1270, CVE-2022-22947, CVE-2022-22963, CVE-2022-22965). Each has
a compile-only `pom.xml`, vulnerable source, and an `EXPECTED.md`.

```bash
for d in tests/cves/CVE-*; do semgrep scan --config semgrep/ "$d"; done
```

**Layer D recall: 5 / 5 fixtures detected by `local` (this pack).**

CI (`.github/workflows/validate.yml`) runs this on every PR and fails
if any fixture stops producing findings.

## External corpus benchmark

External tooling lives at `spring-bench/bench-v2/` (read-only artifact).
Last run: **2026-05-01** (rules-repo SHA `c853c68`, Semgrep 1.134.0,
CodeQL 2.25.3). Note: the v2 numbers were captured **before** the round-2
fixes in this commit history (D1 audit-pack split, D2 severity drop, D3
CodeQL port, D4 SSRF tightening); they describe the rules at SHA
`c853c68`. Re-bench expected after this round.

### Layer B — joychou precision (vuln vs sec endpoints, v2 numbers)

`precision_realistic = TP-on-vuln / (TP-on-vuln + FP-on-sec)`.
The unknown column is endpoints whose URL/method name doesn't classify.

| Rule | TP-on-vuln | FP-on-sec | unknown | precision_realistic |
|---|---|---|---|---|
| `spring-spel-standard-evaluation-context` | 2 | 0 | 0 | 100% |
| `spring-xxe-documentbuilderfactory-default` | 2 | 0 | 2 | 100% |
| `spring-jpa-entity-as-controller-parameter` *(now audit)* | 1 | 0 | 1 | 100% |
| `spring-mvc-view-name-from-user-input` | 2 | 1 | 6 | 67% |
| `spring-xxe-saxparserfactory-default` | 2 | 1 | 0 | 67% |
| `spring-mvc-pojo-parameter-without-requestbody` | 0 | 4 | 2 | 0% |
| `spring-open-redirect-sendredirect-tainted` | 0 | 1 | 1 | 0% |

Round-2 changes likely improve these (the SSRF FP shape that drove the
59-finding noise on OWASP Benchmark is gone; the JPA-entity rule moved
out of the default pack so its low precision no longer drags the
default invocation). Re-bench will confirm.

### Layer A — OWASP BenchmarkJava (v2 numbers)

| Tool | TPR | FPR | Youden Index |
|---|---|---|---|
| local (this pack) | 0.009 | 0.005 | 0.003 |
| Semgrep p/java | 0.685 | 0.386 | 0.299 |
| Semgrep p/security-audit | 0.865 | 0.386 | 0.479 |
| CodeQL | 0.909 | 0.376 | 0.533 |

Caveat: OWASP BenchmarkJava is plain Servlet code (`HttpServletRequest`)
with no Spring annotations and 4 CWE categories overlapping this pack
(CWE-78, CWE-22, CWE-90, CWE-918). The pack is Spring-tuned — it
**cannot** fire on test cases that don't use Spring annotations. Layer A
is included for the industry-standard frame of reference; the meaningful
numbers for this pack are in Layers B and D.

For full per-CWE breakdowns, codeflows, and per-rule finding counts see
`spring-bench/bench-v2/BENCHMARKS.md`.
