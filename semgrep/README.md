# Semgrep rules — Spring web security

```bash
semgrep --config spring-security-rules/semgrep path/to/app
```

Taint-mode where it cuts noise; plain patterns where the source/sink is
unconditionally bad.

| File | Catches | CVE anchors |
|---|---|---|
| `spring-spel-injection.yml` | tainted string into `SpelExpressionParser`/`Expression`; `StandardEvaluationContext` | CVE-2017-8046, CVE-2018-1273, CVE-2022-22963 |
| `spring-data-binder-mass-assignment.yml` | POJO param without `@RequestBody`; `@InitBinder` not blocking `class.*`; JPA entity as param | CVE-2022-22965, CVE-2022-22968, CVE-2024-38820 |
| `spring-ssrf.yml` | tainted URL into RestTemplate/WebClient/HttpClient/OkHttp/RestClient | — |
| `spring-uricomponents-validation.yml` | `UriComponentsBuilder.fromUriString(...)` + host check | CVE-2024-22243 / 22259 / 22262 |
| `spring-open-redirect.yml` | `redirect:` + tainted, `sendRedirect`, `RedirectView`, `Location` | OWASP A01 |
| `spring-path-traversal.yml` | tainted path into `FileSystemResource`/`PathResource`/`UrlResource`/`getResource("file:")` | CVE-2024-38816, CVE-2016-9878 |
| `spring-unsafe-deserialization.yml` | exporter beans, Jackson `enableDefaultTyping`, `ObjectInputStream` from HTTP | CVE-2016-1000027 |
| `spring-authorization-bypass.yml` | regex matchers with `.`, mvc/ant mix, security annotations on interface | CVE-2022-22978, CVE-2023-20860, CVE-2024-38821, CVE-2025-41248/49 |
| `spring-jndi-injection.yml` | tainted name into `Context.lookup`/`JndiTemplate.lookup`; LDAP filter concat | — |
| `spring-xxe.yml` | `Jaxb2Marshaller` `processExternalEntities=true`, default JAXP factories, XStream w/o allowlist | OWASP A05 |
| `spring-ssti.yml` | view name from user input; `templateEngine.process(tainted, ...)` | OWASP A03 |
| `spring-csrf-disabled.yml` | `http.csrf().disable()` and lambda variants | OWASP A05 |
| `spring-sql-injection.yml` | `JdbcTemplate`/`EntityManager` queries built by string concat | OWASP A03 |
| `spring-permissive-cors.yml` | `@CrossOrigin("*")`, `addAllowedOrigin("*")` + credentials | OWASP A05 |
| `spring-insecure-cookies.yml` | Cookie without secure/httpOnly | OWASP A05 |
| `spring-cloud-function-routing.yml` | `RoutingFunction` / `spring.cloud.function.routing-expression` header | CVE-2022-22963 |
| `spring-cloud-gateway-actuator.yml` | exposed gateway actuator | CVE-2022-22947 |
| `spring-rce-runtime-exec.yml` | tainted into `Runtime.exec`/`ProcessBuilder` | OWASP A03 |
