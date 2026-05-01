# spring-mvc-pojo-parameter-without-requestbody — @RequestParam fix

v3 triage on this rule produced 4 TP / 4 FP. Three of the FPs were
real pattern bugs: the rule's exclusion list only matched the bare-
annotation form (`@RequestParam`), missing the arg-bearing form
(`@RequestParam("name")`) which is by far the more common shape in
real Spring code. A fourth FP came from an unannotated Spring
infrastructure type (`RedirectAttributes`) that wasn't on the
exclusion list.

## v3 triage FPs (3 + 1)

| # | File | Line | Shape | Why old rule fired |
|---|---|---|---|---|
| 1 | `spring-petclinic-ms/spring-petclinic-visits-service/src/main/java/org/springframework/samples/petclinic/visits/web/VisitResource.java` | 72 | `@RequestParam("petId") List<Integer> petIds` | `pattern-not: @RequestParam $T $P` didn't match because the annotation has args |
| 2 | `tutorials/spring-boot-modules/spring-boot-basic-customization-2/src/main/java/com/baeldung/typeconversion/converter/controller/StringToEmployeeConverterController.java` | 13 | `@RequestParam("employee") Employee employee` | same: arg-bearing annotation form |
| 3 | `joychou/src/main/java/org/joychou/controller/FileUpload.java` | 50 | `@RequestParam("file") MultipartFile file, RedirectAttributes redirectAttributes` | first param: arg-bearing annotation; second param: unannotated `RedirectAttributes` not on the infra exclusion list |

## Pattern change

Old:

```yaml
- pattern-not: |
    $RT $M(..., @RequestBody $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @PathVariable $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestParam $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestHeader $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @CookieValue $T $P, ...) { ... }
```

New (cover both bare and arg-bearing forms for every annotation):

```yaml
- pattern-not: |
    $RT $M(..., @RequestBody(...) $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestBody $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @PathVariable(...) $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @PathVariable $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestParam(...) $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestParam $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestHeader(...) $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @RequestHeader $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @CookieValue(...) $T $P, ...) { ... }
- pattern-not: |
    $RT $M(..., @CookieValue $T $P, ...) { ... }
```

`$T` already binds to `List<Integer>` and qualified type names — the
prompt's hypothesis about generic-type binding turned out not to be
the root cause; the missing `(...)` form was.

Also added Spring infrastructure types to the unannotated-param
exclusion list: `RedirectAttributes`, `HttpSession`, `ModelMap`,
`WebRequest`, `NativeWebRequest`, `ServerHttpRequest`,
`ServerHttpResponse`, `UriComponentsBuilder`, `SessionStatus`.

## Validation

Scan results before and after, on the three v3-FP files:

| File | Before | After |
|---|---|---|
| VisitResource.java | 1 finding (L72) | 0 findings |
| StringToEmployeeConverterController.java | 1 finding (L13) | 0 findings |
| FileUpload.java | 1 finding (L50) | 0 findings |

Spring4Shell PoC still detected (no recall regression):

```
$ semgrep scan --config semgrep/spring-data-binder-mass-assignment.yml \
    tests/cves/CVE-2022-22965/src/main/java/example/HelloController.java
spring-mvc-pojo-parameter-without-requestbody  HelloController.java:21
spring-mvc-pojo-parameter-without-requestbody  HelloController.java:28
```

Three new fixture cases added to
`tests/spring-data-binder-mass-assignment.java` lock in the fix.
