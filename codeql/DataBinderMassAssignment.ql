/**
 * @name Spring controller takes a domain POJO without @RequestBody
 * @description Controller method has a POJO parameter that isn't a primitive,
 *              a Spring infra type, nor annotated with @RequestBody /
 *              @PathVariable / @RequestParam / @RequestHeader / @ModelAttribute /
 *              @CookieValue. WebDataBinder will then bind every form/query
 *              parameter onto the object's property tree (`a.b.c=...`),
 *              enabling mass assignment and the Spring4Shell
 *              class.module.classLoader chain (CVE-2022-22965, CVE-2022-22968,
 *              CVE-2024-38820).
 * @kind problem
 * @id java/spring/databinder-mass-assignment
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-915
 *       spring
 *       spring4shell
 */

import java
import lib.SpringSinks

predicate isInfrastructureType(Type t) {
  t.(RefType).hasQualifiedName("javax.servlet.http",
      ["HttpServletRequest", "HttpServletResponse", "HttpSession", "Cookie"])
  or
  t.(RefType).hasQualifiedName("jakarta.servlet.http",
      ["HttpServletRequest", "HttpServletResponse", "HttpSession", "Cookie"])
  or
  t.(RefType).hasQualifiedName("org.springframework.ui", "Model")
  or
  t.(RefType).hasQualifiedName("org.springframework.ui", "ModelMap")
  or
  t.(RefType).hasQualifiedName("org.springframework.validation", "BindingResult")
  or
  t.(RefType).hasQualifiedName("org.springframework.web.multipart", "MultipartFile")
  or
  t.(RefType).hasQualifiedName("java.security", "Principal")
  or
  t.(RefType).hasQualifiedName("org.springframework.security.core", "Authentication")
  or
  t.(RefType).hasQualifiedName("org.springframework.data.domain", ["Pageable", "Sort"])
  or
  t.(RefType).hasQualifiedName("java.util", ["Locale", "TimeZone", "UUID"])
  or
  t instanceof PrimitiveType
  or
  t instanceof BoxedType
  or
  t.(RefType).hasQualifiedName("java.lang", "String")
}

predicate isRequestParameter(Parameter p) {
  exists(Annotation a | a = p.getAnAnnotation() |
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
        ["RequestBody", "PathVariable", "RequestParam", "RequestHeader", "ModelAttribute",
          "CookieValue", "MatrixVariable"])
  )
}

predicate isJpaEntity(RefType t) {
  t.getAnAnnotation()
      .getType()
      .hasQualifiedName("javax.persistence", "Entity")
  or
  t.getAnAnnotation()
      .getType()
      .hasQualifiedName("jakarta.persistence", "Entity")
}

from Method m, Parameter p, string note
where
  isSpringController(m.getDeclaringType()) and
  isRequestMappingMethod(m) and
  p = m.getAParameter() and
  not isInfrastructureType(p.getType()) and
  not isRequestParameter(p) and
  (
    if isJpaEntity(p.getType())
    then note = "JPA @Entity used as controller parameter"
    else note = "POJO controller parameter without @RequestBody"
  )
select p, note + " in " + m.getName() + "."
