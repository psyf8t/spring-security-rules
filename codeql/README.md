# CodeQL queries — Spring web security

```bash
codeql database create db --language=java \
    --command="mvn -B -DskipTests clean package"

codeql pack install spring-security-rules/codeql
codeql database analyze db spring-security-rules/codeql \
    --format=sarif-latest --output=results.sarif
```

`lib/`:

- `SpringSources.qll` — `RemoteFlowSource` subclasses for controller params,
  WebFlux `ServerHttpRequest`, STOMP messages.
- `SpringSinks.qll` — sinks for SpEL parser, outgoing HTTP clients, file
  resources, redirect APIs, JNDI lookup, SQL/JPQL, Runtime/ProcessBuilder.

| Query | Catches | CVE anchors |
|---|---|---|
| `SpelInjection.ql` | source → `SpelExpressionParser.parseExpression` | CVE-2017-8046, CVE-2018-1273, CVE-2022-22963 |
| `DataBinderMassAssignment.ql` | controller method with POJO param, no `@RequestBody` | CVE-2022-22965, CVE-2022-22968, CVE-2024-38820 |
| `SsrfTaint.ql` | source → outgoing HTTP URL | — |
| `UriComponentsHostValidation.ql` | `UriComponentsBuilder.fromUriString` + `getHost()` | CVE-2024-22243 |
| `OpenRedirect.ql` | source → sendRedirect / RedirectView / Location | OWASP A01 |
| `PathTraversal.ql` | source → Resource/Path/File ctor | CVE-2024-38816, CVE-2016-9878 |
| `UnsafeDeserialization.ql` | exporter beans, Jackson default typing, `ObjectInputStream` from HTTP | CVE-2016-1000027 |
| `AuthorizationBypassPatterns.ql` | regex matchers with `.`; security annotations on interface | CVE-2022-22978, CVE-2025-41248/49 |
| `CsrfDisabled.ql` | `http.csrf().disable()` | OWASP A01 |
| `JndiInjection.ql` | source → `Context.lookup` / `JndiTemplate.lookup` | — |
| `XxeMisconfig.ql` | unhardened JAXP factories; `Jaxb2Marshaller.processExternalEntities=true` | OWASP A05 |
| `Ssti.ql` | source → view name return / `templateEngine.process` | OWASP A03 |
| `SqlInjection.ql` | source → JdbcTemplate / EntityManager (concat) | OWASP A03 |
| `PermissiveCors.ql` | `@CrossOrigin("*")`, `addAllowedOriginPattern("*")` + credentials | OWASP A05 |
| `InsecureCookies.ql` | Cookie/ResponseCookie missing secure+httpOnly | OWASP A05 |
| `RuntimeExec.ql` | source → Runtime.exec / ProcessBuilder | OWASP A03 |
