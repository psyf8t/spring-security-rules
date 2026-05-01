# Spring web-security rules

Custom Semgrep + CodeQL rules for Spring (Framework, Boot, Security, Cloud,
Data, WebFlux, Cloud Function/Gateway). Built off public CVEs but matching on
*the development pattern that produced them*, not the specific advisory — so
they fire on the next variant too.

- `semgrep/` — Semgrep YAML rules (java; a couple of generic configs).
- `codeql/`  — CodeQL queries plus a small qll lib (qlpack: java).
- `tests/`   — fixtures (`tests/spring-*.{java,properties}` paired by
  basename with their YAML; `tests/cves/CVE-*/` synthetic modules).

---

## Running

### Semgrep

```bash
semgrep --config semgrep/ path/to/app
```

### CodeQL

```bash
codeql database create db --language=java --command="mvn -B clean package -DskipTests"
codeql database analyze db codeql/ --format=sarif-latest --output=results.sarif
```

`codeql/qlpack.yml` depends on `codeql/java-all`.

---

## Test suite

The repo's regression baseline lives in `tests/`. Two layers:

1. Per-rule paired fixtures, run via `semgrep test`. Each fixture file is
   paired with its YAML by basename:

   ```bash
   for f in tests/spring-*.java tests/spring-*.properties; do
     base=$(basename "$f")
     stem=${base%.*}; stem=${stem%.gateway}
     semgrep test --config "semgrep/${stem}.yml" "$f"
   done
   ```

   `// ruleid:` / `// ok:` / `// todoruleid:` markers on the line above
   the code being checked.

2. Synthetic CVE modules under `tests/cves/CVE-*/`, each with a
   compile-only `pom.xml`, the vulnerable source, and an `EXPECTED.md`
   table of rule ids × lines:

   ```bash
   for d in tests/cves/CVE-*; do semgrep scan --config semgrep/ "$d"; done
   ```

CI (`.github/workflows/validate.yml`) runs both on every PR.

> Layout note: nested `tests/rules/<rule-id>/` directories are not yet
> supported by `semgrep test` ("split of tests/ and rules/ is not supported
> yet"). The flat basename-paired layout above is the one Semgrep
> documents.

---

## Coverage matrix

For each family: which Semgrep rule(s) cover it, the in-repo regression
fixture proving recall, and a confidence label (HIGH / MEDIUM / LOW). The
external benchmark output is in `BENCHMARKS.md`.

| Family | Rule id(s) | Fixture | Confidence |
|---|---|---|---|
| SpEL injection | `spring-spel-injection-parse-expression`, `spring-spel-standard-evaluation-context`, `spring-spel-value-annotation-concat`, `spring-spel-expression-getvalue-tainted` | `tests/cves/CVE-2017-8046/`, `tests/cves/CVE-2018-1270/` | HIGH (servlet sources); MEDIUM (STOMP — source family missing) |
| Mass assignment / Spring4Shell | `spring-mvc-pojo-parameter-without-requestbody`, `spring-init-binder-missing-class-disallow`, `spring-jpa-entity-as-controller-parameter`, `spring-jpa-entity-as-controller-parameter-precise` | `tests/cves/CVE-2022-22965/`, `tests/spring-data-binder-mass-assignment.java` | HIGH (pojo + init-binder); LOW (loose JPA — see Known limitations); MARKER-ONLY (precise JPA — see Known limitations) |
| SSRF | `spring-ssrf-tainted-http-client`, `spring-rest-template-default-redirect-policy` | (paired tests pending) | MEDIUM |
| URI host validation | `spring-uricomponents-host-validation-pattern`, `spring-uricomponents-from-tainted` | `tests/spring-uricomponents-validation.java` | HIGH |
| Open redirect | `spring-open-redirect-prefix-concat`, `spring-open-redirect-sendredirect-tainted` | (paired tests pending) | MEDIUM |
| Path traversal | `spring-path-traversal-resource-from-tainted`, `spring-routerfunctions-resources-tainted-base`, `spring-resource-handler-broad-pattern` | (paired tests pending) | MEDIUM |
| Insecure deserialization | `spring-httpinvoker-exporter-bean`, `spring-jackson-default-typing-enabled`, `spring-objectinputstream-from-http`, `spring-xml-decoder` | `tests/spring-unsafe-deserialization.java` | HIGH |
| Authorization bypass | `spring-security-regex-matcher-without-dotall`, `spring-security-csrf-disabled`, `spring-security-permitall-on-admin-actuator`, `spring-security-mixed-mvc-ant-matchers`, `spring-security-annotation-on-interface`, `spring-webflux-static-resource-not-permitall` | `tests/spring-authorization-bypass.java` | MEDIUM |
| JNDI | `spring-jndi-lookup-tainted`, `spring-ldap-filter-concat` | `tests/spring-jndi-injection.java` | HIGH |
| XXE | `spring-xxe-jaxb2marshaller-process-external`, `spring-xxe-documentbuilderfactory-default`, `spring-xxe-saxparserfactory-default`, `spring-xxe-xmlinputfactory-default`, `spring-xstream-default` | `tests/spring-xxe.java` | HIGH |
| SSTI | `spring-mvc-view-name-from-user-input`, `spring-template-engine-tainted-template-string` | (paired tests pending) | MEDIUM |
| CSRF | `spring-security-csrf-disable` | (paired tests pending) | HIGH |
| SQL/JPQL injection | `spring-jdbctemplate-string-concat`, `spring-jpa-createquery-string-concat`, `spring-data-jpa-query-with-spel-pound` | (paired tests pending) | HIGH |
| CORS | `spring-crossorigin-wildcard`, `spring-cors-config-wildcard-with-credentials` | `tests/spring-permissive-cors.java` | HIGH |
| Cookies | `spring-cookie-missing-secure-httponly`, `spring-responsecookie-not-secure` | `tests/spring-insecure-cookies.java` | MEDIUM |
| Spring Cloud Function | `spring-cloud-function-routing-function`, `spring-cloud-function-routing-header-direct-eval` | `tests/cves/CVE-2022-22963/`, `tests/spring-cloud-function-routing.java` | MEDIUM |
| Spring Cloud Gateway | `spring-cloud-gateway-actuator-exposed`, `spring-actuator-broadly-exposed` | `tests/cves/CVE-2022-22947/`, `tests/spring-cloud-gateway-actuator.{,gateway.}properties` | MEDIUM (gateway: needs same-file gateway config or pom.xml triage) |
| RCE (Runtime.exec) | `spring-runtime-exec-tainted` | (paired tests pending) | MEDIUM |

CodeQL queries are listed in `codeql/README.md`; they cover the same families
and are validated by `codeql query compile` on a label-gated CI job.

---

## Known limitations

- **Cross-file `@Entity` detection** — `spring-jpa-entity-as-controller-parameter-precise`
  cannot reliably fire when the `@Entity` class lives in a different file from
  the controller (the metavariable-pattern operates on the type-name binding,
  not on the project's symbol table). Real Spring projects keep entities in a
  separate package, so the precise rule reports zero findings on
  spring-petclinic-ms and similar layouts. The loose companion
  `spring-jpa-entity-as-controller-parameter` (INFO, LOW confidence) is the
  practical signal.
- **STOMP / WebSocket SpEL source** — `spring-spel-injection-parse-expression`'s
  taint sources cover servlet/controller params but not
  `StompHeaderAccessor.getFirstNativeHeader`. CVE-2018-1270 still trips
  `spring-spel-standard-evaluation-context`, which is the secondary signal.
- **CodeQL local validation** — CodeQL CLI is not installed by default
  in this repo; queries are compile-checked only by the gated CI job.
- **Generic-mode actuator/gateway correlation** — the
  `spring-cloud-gateway-actuator-exposed` rule cannot read `pom.xml` from
  a YAML/properties file. It correlates within a single config file or
  defers to `mvn dependency:tree | grep gateway` for triage.
- **Runtime / framework-only behaviors** — anything that depends on
  classpath scanning, runtime registration, or environment-driven SpEL
  evaluation (Cloud Config server, etc.) is out of scope for
  source-only static rules.

---

## Benchmarks

See [BENCHMARKS.md](BENCHMARKS.md) — short summary of the in-repo regression
baseline (`tests/cves/`) and a pointer to the external corpus run.

---

## Notes on how rules were written

Rules deliberately fire on the *pattern*, not the vendor version. Expect more
noise on tests and demo code than a CVE-version detector would give you. All
rules carry severity + `metadata.cwe` + references; many use `taint-mode` with
explicit sources/sinks. Several rules carry `metadata.confidence` (LOW, MEDIUM,
HIGH) and `metadata.notes` documenting their constraints.
