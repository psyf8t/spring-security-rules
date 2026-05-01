# Benchmarks

Bench v3, run 2026-05-01. Tool versions: semgrep 1.134.0, codeql 2.25.3.
Full report: [bench-v3/BENCHMARKS-FULL.md](../benches/spring-bench/bench-v3/BENCHMARKS-FULL.md).

## TL;DR
- Layer D recall (in-repo CVE fixtures): **5/5** detected by `local`.
- Layer B precision_realistic on joychou: **8 TP / 7 FP = 53%** (vs v2's 56%); 21 unknown-endpoint findings excluded. (round-2 fixes did not target joychou-specific FPs; the 7 FPs are tracked in fix-rules round-3 — see the pojo-parameter pattern fix below.)
- Layer C real-world CVEs (HF CWE-Bench-Java): 1/5 detected by `local`.
- Layer A Youden Index on overlap CWEs (CWE-22, CWE-78, CWE-89, CWE-90): **0.008** (TP=12 FP=7).
- Default pack: 47 rules, all load cleanly. Audit pack: 2 rules. Opt-in.

## Corpus
Pinned SHAs:
```
owasp-benchmark          b06d6efaebd577a327514364951916e7df3290b4
joychou                  4711f4e186258c6e0dd5c3863e7c9592e7e9026a
spring-petclinic         c7ee170434ec3e369fdc9201290ba2ea4c92b557
spring-petclinic-ms      9a76b4e34cd75f3d6bfa6f15775bf996c59e8989
tutorials                4634211d8594a21f071ca9ab461f92463a010788
rules-repo               f81c528fbf17cff2de8e5763adf35bd2dae80ac4
```

## Layer D — In-repo CVE fixtures
| CVE | local | p/java | p/sec-audit | p/owasp | r/java.spring | CodeQL |
|---|---|---|---|---|---|---|
| CVE-2017-8046 | ✓ | ✗ | ✗ | ✗ | ✗ | partial |
| CVE-2018-1270 | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| CVE-2022-22947 | ✓ | ✗ | ✗ | partial | partial | n/a |
| CVE-2022-22963 | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| CVE-2022-22965 | ✓ | ✗ | ✗ | ✗ | ✗ | partial |

## Layer B — joychou (default-pack precision)
Rules with sample size ≥ 3 (TP+FP+unknown):
| Rule | TP-vuln | FP-sec | unknown | precision |
|---|---|---|---|---|
| `spring-cookie-missing-secure-httponly` | 0 | 0 | 6 | n/a |
| `spring-mvc-pojo-parameter-without-requestbody` | 0 | 4 | 2 | 0% |
| `spring-mvc-view-name-from-user-input` | 2 | 1 | 6 | 67% |
| `spring-xxe-documentbuilderfactory-default` | 2 | 0 | 2 | 100% |
| `spring-xxe-saxparserfactory-default` | 2 | 1 | 0 | 67% |

Triage outcomes on top default-pack rules (clean corpus + joychou unknown):
| Rule | TP | FP | MAYBE | precision |
|---|---|---|---|---|
| `spring-actuator-broadly-exposed` | 6 | 0 | 0 | 100% |
| `spring-cookie-missing-secure-httponly` | 2 | 0 | 0 | 100% |
| `spring-jackson-default-typing-enabled` | 1 | 0 | 0 | 100% |
| `spring-mvc-pojo-parameter-without-requestbody` | 4 | 4 | 0 | 50% |
| `spring-rest-template-default-redirect-policy` | 6 | 0 | 0 | 100% |
| `spring-runtime-exec-tainted` | 1 | 0 | 0 | 100% |
| `spring-security-csrf-disable` | 5 | 1 | 0 | 83% |
| `spring-security-csrf-disabled` | 4 | 2 | 0 | 67% |

> Rules with sampled n ≤ 2 omitted from precision column; see `bench-v3/artifacts/triage.json` for full verdicts.

Two rules had triage sample size n=2 and are omitted from the precision table:
`spring-mvc-view-name-from-user-input` (both FPs were on `@RestController` methods
where the returned String is a JSON/JSONP payload, not a view name) and
`spring-xxe-documentbuilderfactory-default` (both FPs were on `SafeDomainParser`,
which uses a hard-coded `ClassPathResource` — no attacker-controlled XML). Both
indicate narrow rule scope issues, not 0% precision in deployment.

## Layer A — OWASP BenchmarkJava
| Tool | Youden (all 11 cats) | Youden (overlap CWEs) |
|---|---|---|
| local | 0.003 | 0.008 |
| p/java | 0.299 | 0.156 |
| p/sec-audit | 0.479 | 0.217 |
| p/owasp | 0.299 | 0.156 |
| r/java.spring | 0.000 | 0.000 |
| CodeQL | 0.530 | 0.362 |

> **Layer A is included as the industry-standard frame of reference, not as a primary quality signal for this pack.** OWASP BenchmarkJava uses `HttpServletRequest.getParameter` as the taint source on every test case; this pack's sources are `@RequestParam`, `@PathVariable`, `@RequestHeader`, `ServerHttpRequest`. Of OWASP's 11 CWE categories, this pack covers 4 (CWE-22, CWE-78, CWE-89, CWE-90); cookie-related rules use CWE-1004 and CWE-1336, which are not in OWASP Benchmark's category set. The rest are out of scope by design. **Score on the overlap: Youden = 0.008 (TP=12 FP=7).**[^overlap] The aggregate-over-all-categories score (0.003) is included for comparability with Sonar/Veracode/CodeQL published numbers.

[^overlap]: 4-CWE recompute on this run yields the same Youden Index (0.008, TP=12, FP=7) because OWASP-Benchmark's CWE-614 cases produced zero findings from this pack.

## Layer C — Real-world CVE recall
- ✗ CVE-2020-5410 (CWE-022, `spring-cloud__spring-cloud-config_CVE-2020-5410_2.1.8.RELEASE`)
- ✓ CVE-2020-5405 (CWE-022, `spring-cloud__spring-cloud-config_CVE-2020-5405_2.1.6.RELEASE`)
- ✗ CVE-2018-1260 (CWE-094, `SpringSource__spring-security-oauth_CVE-2018-1260_2.3.2.RELEASE`)
- ✗ CVE-2022-22965 (CWE-094, `spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE`)
- ✗ CVE-2022-22947 (CWE-094, `spring-cloud__spring-cloud-gateway_CVE-2022-22947_3.0.6`)

## Known gaps
- Layer A overlap is intentionally narrow (4 CWEs); the rest are out of scope by design — extending to e.g. crypto/XSS would mean adding non-Spring-tuned rules to a Spring pack.
- joychou unknown-endpoint findings (no `/vul` or `/sec` in URL/method) need human verdict; counts in the table exclude them.
- 7 of 18 default-pack rule files still ship without paired test fixtures (round-2 fix-rules: out of bench scope, tracked in fix-rules backlog).
- `pyn3rd/Spring-Boot-Vulnerability` and Contrast were dropped from v3: pyn3rd has 0 .java files (writeups only); Contrast is ~10 files — neither produces useful signal vs. joychou.
- Vul4J skipped: no Python-3.13-compatible distribution on PyPI.

## Reproduction
See `bench-v3/run.sh`. Replace pinned SHAs as needed.
