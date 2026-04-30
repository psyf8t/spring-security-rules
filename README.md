# Spring web-security rules

Custom Semgrep + CodeQL rules for Spring (Framework, Boot, Security, Cloud,
Data, WebFlux, Cloud Function/Gateway). Built off public CVEs but matching on
*the development pattern that produced them*, not the specific advisory — so
they fire on the next variant too.

- `semgrep/` — Semgrep YAML rules (java; a couple of generic configs).
- `codeql/`  — CodeQL queries plus a small qll lib (qlpack: java).

---

## Vulnerability families

Each entry: representative CVEs, what the bad code looks like, what the rule
matches, where it tends to false-positive.

### SpEL injection

Anchors: CVE-2017-8046 (Data REST PATCH), CVE-2018-1273 (Data Commons property
paths), CVE-2018-1270 (STOMP selectors), CVE-2022-22963 (Cloud Function header
routing), CVE-2022-22950 / CVE-2023-20861 / CVE-2023-20863 (SpEL DoS).

Anything that lands an attacker string in `SpelExpressionParser.parseExpression`
or `Expression.getValue/setValue` is RCE via `T(java.lang.Runtime).getRuntime().exec(...)`.
The Cloud Function CVE is the textbook case — a header
(`spring.cloud.function.routing-expression`) parsed as SpEL. The DoS CVEs are
the same parser, no length cap, default `SpelParserConfiguration`.

```java
String expr = request.getParameter("q");
new SpelExpressionParser().parseExpression(expr).getValue();

// templated
parser.parseExpression(userInput, new TemplateParserContext()).getValue(ctx);

// or just the wrong context — gives reflection / T(...) / .class
new StandardEvaluationContext(target);
```

Rules look for: tainted string into `parseExpression`/`parseRaw`, use of
`StandardEvaluationContext` (warn), tainted root in `getValue`/`setValue`,
string concat into `@Value`.

### Mass assignment + Spring4Shell

Anchors: CVE-2022-22965 (RCE via ClassLoader on Tomcat), CVE-2022-22968,
CVE-2024-38820 (case-insensitive `disallowedFields` bypass), CVE-2010-1622.

Three mistakes feed this:

1. Controller takes a POJO with no `@RequestBody` → `WebDataBinder` walks
   `a.b.c=...` paths. Without `setDisallowedFields("class.*", "Class.*",
   "*.class.*", "*.Class.*")` an attacker reaches
   `getClass().getModule().getClassLoader()`.
2. No global `@ControllerAdvice @InitBinder`.
3. Domain entities (JPA, security beans) used directly as method parameters —
   attacker sets `role=ADMIN` for free.

```java
@PostMapping("/users")
String create(User user) { ... }   // no @RequestBody — binds from query/form

@Controller
class C {
    @InitBinder
    void init(WebDataBinder b) { /* no setDisallowedFields */ }
}
```

### SSRF

Anchors: CVE-2024-22243 / 22259 / 22262 (`UriComponentsBuilder` parses userinfo
differently from most libs → host check passes, request goes elsewhere); plus
the generic SSRF in any Spring app.

```java
String url = request.getParameter("u");
restTemplate.getForObject(url, String.class);

URI uri = UriComponentsBuilder.fromUriString(url).build().toUri();
if (!"trusted.example".equals(uri.getHost())) reject();
restTemplate.getForObject(uri, String.class);          // CVE-2024-22243

webClient.get().uri(URI.create(userInput)).retrieve()...
```

Rules: tainted URL into `RestTemplate`/`WebClient`/`RestClient`/JDK
`HttpClient`/OkHttp/Apache HC; specifically the `UriComponentsBuilder` +
`getHost()` shape.

### Open redirect

`return "redirect:" + userInput`, `response.sendRedirect(userInput)`,
`new RedirectView(...)`, `Location` header. No allowlist anywhere.

### Path traversal

Anchors: CVE-2024-38816 (path traversal via `RouterFunctions.resources` with
user-derived base), CVE-2024-38819, CVE-2016-9878 (`ResourceServlet`).

Resolving a resource by a partly-user path with no `Path.normalize()` +
`startsWith(baseDir)`. WebMvc.fn / WebFlux.fn make it especially easy by
returning a `FileSystemResource` built from concat.

```java
@GetMapping("/file")
ResponseEntity<Resource> get(@RequestParam String name) {
    return ResponseEntity.ok(new FileSystemResource(baseDir + "/" + name));
}

router.resources("/static/**", new FileSystemResource(userBase));   // CVE-2024-38816
```

### Insecure deserialization

Anchors: CVE-2016-1000027 (`HttpInvokerServiceExporter`), CVE-2011-2894
(`RmiInvocationHandler`), CVE-2022-22980 (Data MongoDB SpEL),
CVE-2017-4995 (Spring Security OAuth2).

Any endpoint reading a Java-serialised stream from the network:
`HttpInvokerServiceExporter`, `SimpleHttpInvokerServiceExporter`,
`HessianServiceExporter`, `BurlapServiceExporter`, `RmiServiceExporter`,
`JmsInvokerServiceExporter`. Plus Jackson `enableDefaultTyping` /
`activateDefaultTyping(LaissezFaireSubTypeValidator…)`, and `ObjectInputStream`
wrapped around `request.getInputStream()`.

### Authorization bypass

Anchors: CVE-2022-22978 (`.` in regex matcher), CVE-2023-20860 (`**` in
`mvcRequestMatcher` under Boot ≥ 3), CVE-2024-38821 (`//index.html` bypasses
WebFlux static deny rule), CVE-2025-41248 / 41249 (security annotations missed
on parameterised types).

Common shapes:

- `regexMatchers("/admin/.*")` — `.` doesn't match `\n`, so `/admin/x%0a/...`
  slips through.
- Mixing `antMatchers` and `mvcMatchers` under Boot 3 / Security 6.
- URL normalisation (`//`, `;jsessionid=`, `..;`) happening *after* the filter.
- `@PreAuthorize` on a generic interface method that the impl doesn't repeat.
- `permitAll()` on a broad static path + custom `addResourceHandlers`.

### Misc

- **JNDI** — `Context.lookup(userInput)`, `JndiTemplate.lookup`, LDAP filter
  string concat.
- **XXE** — `Jaxb2Marshaller.setProcessExternalEntities(true)`,
  `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory` left at
  defaults, `XStream` without an allowlist.
- **SSTI** — returning a user-controlled view name from a controller; passing
  user data as the *template string* to `templateEngine.process`.
- **CSRF disabled** — `http.csrf().disable()` outside of header-token REST.
- **SQL/JPQL injection** — `JdbcTemplate.queryForObject("…" + name)`,
  `em.createQuery("from User u where u.name='" + n + "'")`.
- **CORS** — `@CrossOrigin("*")`, `addAllowedOriginPattern("*")` + credentials.
- **Cookies** — `new Cookie(...)` without `setSecure`/`setHttpOnly`,
  `ResponseCookie.from(...)` without `secure(true).httpOnly(true)`.
- **Spring Cloud Function** (CVE-2022-22963) — `RoutingFunction` present;
  routing-expression header parsed as SpEL.
- **Spring Cloud Gateway** (CVE-2022-22947) — gateway actuator exposed +
  writeable.
- **STOMP / WebSocket** (CVE-2018-1270, CVE-2025-41254) — default
  `SimpAnnotationMethodMessageHandler` uses `StandardEvaluationContext` for
  selectors; STOMP CSRF can be turned off.

---

## Running

### Semgrep

```bash
semgrep --config spring-security-rules/semgrep path/to/app
```

### CodeQL

```bash
codeql database create db --language=java --command="mvn -B clean package -DskipTests"
codeql database analyze db spring-security-rules/codeql --format=sarif-latest --output=results.sarif
```

`codeql/qlpack.yml` depends on `codeql/java-all`.

---

## Notes

- Rules deliberately fire on the *pattern*, not the vendor version. Expect
  more noise on tests and demo code than a CVE-version detector would give you.
- All rules carry severity + `metadata.cwe` + references.
- Where it pays off, Semgrep rules use `taint-mode` with explicit sources/sinks.
- CodeQL queries use `RemoteFlowSource` and `TaintTracking::Global` so they
  drop straight into Code Scanning.
