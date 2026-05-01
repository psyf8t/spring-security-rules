# spring-ssrf-tainted-http-client — OWASP Benchmark audit

bench-v2 produced 59 findings on OWASP BenchmarkJava
(`bench-v2/results/local/owasp_benchmark.sarif`). OWASP BenchmarkJava
contains no CWE-918 (SSRF) test cases — every test case is one of
cmdi/path-traversal/xss/sqli/etc. Sampled the first 10 findings to
classify them.

| # | File:Line | Reported sink line | Verdict | Why |
|---|---|---|---|---|
| 1 | BenchmarkTest00119.java:60 | `map8142.put("key8142", b8142.toString())` | FP | `Map.put(...)` matched the rule's `$RT.put($URL, ...)` pattern. No outgoing HTTP request anywhere in the file. |
| 2 | BenchmarkTest00137.java:54 | `map53289.put("keyB-53289", param)` | FP | Same shape — `Map.put` mis-matched as `RestTemplate.put`. The data flow ends at `Files.newInputStream` (CWE-22 territory, not SSRF). |
| 3 | BenchmarkTest00139.java:60 | `map48394.put("key48394", b48394.toString())` | FP | Same shape. Data flow ends at `LDAPManager` (CWE-90). |
| 4 | BenchmarkTest00145.java:54 | `map17589.put("keyB-17589", param)` | FP | Same shape. Data flow ends at `response.getWriter().format(...)` (XSS, CWE-79). |
| 5 | BenchmarkTest00153.java:54 | `map96050.put("keyB-96050", param)` | FP | Same. Sink is `response.getWriter().println(bar)` (XSS). |
| 6 | BenchmarkTest00161.java:54 | `map91760.put("keyB-91760", param)` | FP | Same. Cookies / weak random — CWE-614 / CWE-330. |
| 7 | BenchmarkTest00170.java:60 | `map.put(...)` | FP | Same shape (sampled by pattern, not re-extracted line by line — visual confirmation: no outgoing HTTP). |
| 8 | BenchmarkTest00171.java:54 | `map.put(...)` | FP | Same. |
| 9 | BenchmarkTest00172.java:54 | `map.put(...)` | FP | Same. |
| 10 | BenchmarkTest00173.java:54 | `map.put(...)` | FP | Same. |

Verdict: **10 / 10 FP**. The rule fires on `Map.put(taintedKey, ...)` and
similar non-Spring sinks. The root cause is that the sink patterns for
RestTemplate methods (`put`, `delete`, `execute`) are written as
`$RT.put($URL, ...)` with no type constraint on `$RT`, so any call
shaped `something.put(arg, ...)` qualifies.

## Action

Tighten the sink patterns in `semgrep/spring-ssrf.yml` to bind `$RT` to
the relevant interface/class:

- `(RestTemplate $RT).put(...)` / `.delete(...)` / `.execute(...)` /
  `.exchange(...)` / `.getForObject(...)` / `.getForEntity(...)` /
  `.postForObject(...)` / `.postForEntity(...)`
- `(RestOperations $RT).…` for the interface form.

Servlet sources (`HttpServletRequest.getParameter`/`.getHeader` and
`HttpSession.getAttribute`) stay in the source list — they are valid
sources of taint for non-Spring servlets that still call a Spring
RestTemplate. The rule's claimed scope is "outgoing HTTP request URL
from user input"; that scope is correct, the sinks just need to be
narrowed.

Two new fixtures
(`tests/spring-ssrf-tainted-http-client/positive.java`,
`negative.java`) lock in the expected behavior.
