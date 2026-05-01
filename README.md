# Spring web-security rules

Custom Semgrep + CodeQL rules for Spring (Framework, Boot, Security, Cloud,
Data, WebFlux, Cloud Function/Gateway). Built off public CVEs but matching on
*the development pattern that produced them*, not the specific advisory — so
they fire on the next variant too.

- `semgrep/`       — default-on Semgrep YAML rules (java; a couple of generic configs).
- `semgrep-audit/` — opt-in audit rules. Higher noise, run when you're
  reviewing for a specific risk class. Currently: JPA mass-assignment.
- `codeql/`        — CodeQL queries plus a small qll lib (qlpack: java).
- `tests/`         — fixtures (`tests/spring-*.{java,properties}` paired by
  basename with their YAML; `tests/cves/CVE-*/` synthetic CVE modules;
  `tests/rules-audit/` paired fixtures for `semgrep-audit/`).

---

## Running

### Semgrep — default pack

```bash
semgrep --config semgrep/ path/to/app
```

### Semgrep — audit pack (noisier, for targeted review)

```bash
semgrep --config semgrep-audit/ path/to/app
```

You can run both together for a full sweep:

```bash
semgrep --config semgrep/ --config semgrep-audit/ path/to/app
```

### CodeQL

```bash
codeql database create db --language=java --command="mvn -B clean package -DskipTests"
codeql pack install codeql/
codeql database analyze db codeql/ --format=sarif-latest --output=results.sarif
```

`codeql/qlpack.yml` pins `codeql/java-all: ^9.0.4`.

---

## Severity & confidence levels

The pack uses Semgrep `severity` for blocking strength and a `metadata.confidence`
field for how certain the rule's verdict is.

| Severity | Use it for |
|---|---|
| `ERROR` | Always-bad code shape with a known CVE-class outcome. Block PRs. |
| `WARNING` | Pattern that is bad in most contexts. Surface as build warnings. |
| `INFO` | Signal whose verdict depends on context the rule can't see. Filterable. |

| Confidence | Meaning |
|---|---|
| `HIGH` | Pattern is unambiguous; the rule's true-positive rate is the rule's whole point. |
| `MEDIUM` | Pattern is a strong indicator but precision depends on usage. Pair with companion rules where applicable. |
| `LOW` | Heuristic. Expect false positives. Documented in the rule's `metadata.notes`. |

The audit pack's rules carry `metadata.audit: true` and a one-line preamble
in their `message:` so any consumer can spot them.

---

## Test suite

The repo's regression baseline lives in `tests/`. Three layers:

1. **Per-rule paired fixtures** for the default pack:
   ```bash
   for f in tests/spring-*.java tests/spring-*.properties; do
     base=$(basename "$f"); stem=${base%.*}; stem=${stem%.gateway}
     semgrep test --config "semgrep/${stem}.yml" "$f"
   done
   ```

2. **Per-rule paired fixtures** for the audit pack:
   ```bash
   for f in tests/rules-audit/*.java; do
     base=$(basename "$f" .java)
     semgrep test --config "semgrep-audit/${base}.yml" "$f"
   done
   ```

3. **Synthetic CVE modules** under `tests/cves/CVE-*/`, each with a
   compile-only `pom.xml`, vulnerable source, and an `EXPECTED.md`:
   ```bash
   for d in tests/cves/CVE-*; do semgrep scan --config semgrep/ "$d"; done
   ```

Markers: `// ruleid:` / `// ok:` / `// todoruleid:` on the line above the
target code.

CI (`.github/workflows/validate.yml`) runs all three on every PR.

> Layout note: nested `tests/rules/<rule-id>/` directories are not yet
> supported by `semgrep test` ("split of tests/ and rules/ is not supported
> yet"). The flat basename-paired layout above is the one Semgrep documents.

---

## Coverage matrix

For each family: which rule(s) cover it, in which pack, the in-repo regression
fixture proving recall, and a confidence label. v2 bench numbers and detail
are in [BENCHMARKS.md](BENCHMARKS.md).

| Family | Pack | Rule id(s) | Fixture | Confidence |
|---|---|---|---|---|
| SpEL injection | default | `spring-spel-injection-parse-expression`, `spring-spel-standard-evaluation-context`, `spring-spel-value-annotation-concat`, `spring-spel-expression-getvalue-tainted` | `tests/cves/CVE-2017-8046/`, `tests/cves/CVE-2018-1270/` | HIGH (servlet sources); MEDIUM (STOMP — source family missing) |
| Mass assignment / Spring4Shell | default | `spring-mvc-pojo-parameter-without-requestbody`, `spring-init-binder-missing-class-disallow` | `tests/cves/CVE-2022-22965/`, `tests/spring-data-binder-mass-assignment.java` | HIGH (paired) — pojo rule alone is MEDIUM, init-binder rule confirms missing global mitigation |
| Mass assignment — JPA entity | **audit** | `spring-jpa-entity-as-controller-parameter`, `spring-jpa-entity-as-controller-parameter-precise` | `tests/rules-audit/spring-jpa-mass-assignment-audit.java` | LOW (loose); MARKER-ONLY (precise — see Known limitations) |
| SSRF | default | `spring-ssrf-tainted-http-client`, `spring-rest-template-default-redirect-policy` | `tests/spring-ssrf.java` | MEDIUM |
| URI host validation | default | `spring-uricomponents-host-validation-pattern`, `spring-uricomponents-from-tainted` | `tests/spring-uricomponents-validation.java` | HIGH |
| Open redirect | default | `spring-open-redirect-prefix-concat`, `spring-open-redirect-sendredirect-tainted` | (paired tests pending) | MEDIUM |
| Path traversal | default | `spring-path-traversal-resource-from-tainted`, `spring-routerfunctions-resources-tainted-base`, `spring-resource-handler-broad-pattern` | (paired tests pending) | MEDIUM |
| Insecure deserialization | default | `spring-httpinvoker-exporter-bean`, `spring-jackson-default-typing-enabled`, `spring-objectinputstream-from-http`, `spring-xml-decoder` | `tests/spring-unsafe-deserialization.java` | HIGH |
| Authorization bypass | default | `spring-security-regex-matcher-without-dotall`, `spring-security-csrf-disabled`, `spring-security-permitall-on-admin-actuator`, `spring-security-mixed-mvc-ant-matchers`, `spring-security-annotation-on-interface`, `spring-webflux-static-resource-not-permitall` | `tests/spring-authorization-bypass.java` | MEDIUM (regex/mismatch); LOW (csrf-disabled — context-dependent) |
| JNDI | default | `spring-jndi-lookup-tainted`, `spring-ldap-filter-concat` | `tests/spring-jndi-injection.java` | HIGH |
| XXE | default | `spring-xxe-jaxb2marshaller-process-external`, `spring-xxe-documentbuilderfactory-default`, `spring-xxe-saxparserfactory-default`, `spring-xxe-xmlinputfactory-default`, `spring-xstream-default` | `tests/spring-xxe.java` | HIGH |
| SSTI | default | `spring-mvc-view-name-from-user-input`, `spring-template-engine-tainted-template-string` | (paired tests pending) | MEDIUM |
| CSRF | default | `spring-security-csrf-disable` | (paired tests pending) | LOW (context-dependent) |
| SQL/JPQL injection | default | `spring-jdbctemplate-string-concat`, `spring-jpa-createquery-string-concat`, `spring-data-jpa-query-with-spel-pound` | (paired tests pending) | HIGH |
| CORS | default | `spring-crossorigin-wildcard`, `spring-cors-config-wildcard-with-credentials` | `tests/spring-permissive-cors.java` | HIGH |
| Cookies | default | `spring-cookie-missing-secure-httponly`, `spring-responsecookie-not-secure` | `tests/spring-insecure-cookies.java` | MEDIUM |
| Spring Cloud Function | default | `spring-cloud-function-routing-function`, `spring-cloud-function-routing-header-direct-eval` | `tests/cves/CVE-2022-22963/`, `tests/spring-cloud-function-routing.java` | MEDIUM |
| Spring Cloud Gateway | default | `spring-cloud-gateway-actuator-exposed`, `spring-actuator-broadly-exposed` | `tests/cves/CVE-2022-22947/`, `tests/spring-cloud-gateway-actuator.{,gateway.}properties` | MEDIUM (gateway: needs same-file gateway config or pom.xml triage) |
| RCE (Runtime.exec) | default | `spring-runtime-exec-tainted` | (paired tests pending) | MEDIUM |

CodeQL queries cover the same families and live in `codeql/`; they're
compile-checked by the `codeql-compile` CI job. See `codeql/README.md`.

---

## Known limitations

- **Cross-file `@Entity` detection** — `spring-jpa-entity-as-controller-parameter-precise`
  (in `semgrep-audit/`) cannot reliably fire when the `@Entity` class lives in
  a different file from the controller. The metavariable-pattern operates on
  the type-name binding ("Pet"), not on the file body — there is no `@Entity`
  text in that range. Real Spring projects keep entities in a separate package,
  so the precise rule reports zero findings on spring-petclinic-ms and similar
  layouts. The loose companion `spring-jpa-entity-as-controller-parameter`
  (audit, INFO, LOW confidence) is the practical signal until cross-file
  resolution (Semgrep Pro inter-file mode, or external symbol indexing) is
  wired up.
- **STOMP / WebSocket SpEL source** — `spring-spel-injection-parse-expression`'s
  taint sources cover servlet/controller params but not
  `StompHeaderAccessor.getFirstNativeHeader`. CVE-2018-1270 still trips
  `spring-spel-standard-evaluation-context`, which is the secondary signal.
- **Generic-mode actuator/gateway correlation** —
  `spring-cloud-gateway-actuator-exposed` cannot read `pom.xml` from a YAML
  or properties file. It correlates within a single config file or defers
  to `mvn dependency:tree | grep gateway` for triage.
- **SSRF sink coverage** — round 2 dropped `RestTemplate.put/delete/execute`
  patterns because their names alias `Map.put`, `Statement.execute`,
  etc., and Semgrep's open-source type tracking can't reliably resolve a
  `restTemplate` field reference. Consumers using those methods specifically
  should add a custom rule with `(RestTemplate $RT).put(...)` and accept the
  type-resolution misses.
- **CodeQL marker tests** — qltest harness deferred. Queries are
  compile-checked in CI (`codeql-compile` job) and the rule semantics are
  exercised by the in-repo CVE fixtures via the standard CodeQL DB scan.
  See the round-2 D3 commit body for context on the qltest layout
  limitations.
- **Runtime / framework-only behaviors** — anything that depends on
  classpath scanning, runtime registration, or environment-driven SpEL
  evaluation (Cloud Config server, etc.) is out of scope for source-only
  static rules.

---

## Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) — in-repo regression baseline plus the
v2 corpus run summary (joychou precision, OWASP Benchmark caveats).

---

## Notes on how rules were written

Rules deliberately fire on the *pattern*, not the vendor version. Expect more
noise on tests and demo code than a CVE-version detector would give you. All
rules carry severity + `metadata.cwe` + references; many use `taint-mode` with
explicit sources/sinks. Rules carry `metadata.confidence` (LOW / MEDIUM / HIGH)
and `metadata.notes` documenting their constraints. Audit-pack rules also
carry `metadata.audit: true`.
