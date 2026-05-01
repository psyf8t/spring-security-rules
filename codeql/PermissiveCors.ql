/**
 * @name Permissive CORS configuration
 * @description @CrossOrigin(origins = "*"); CorsConfiguration with wildcard
 *              origin + setAllowCredentials(true) (or
 *              addAllowedOriginPattern("*"), which bypasses the wildcard +
 *              credentials browser restriction starting from Spring 5.3).
 * @kind problem
 * @id java/spring/permissive-cors
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-942
 *       spring
 */

import java

predicate crossOriginWildcard(Annotation a, string what) {
  a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CrossOrigin") and
  (
    not exists(a.getValue("origins")) and what = "@CrossOrigin (default origins=*)"
    or
    exists(StringLiteral sl |
      sl = a.getValue("origins").(ArrayInit).getAnInit() or sl = a.getValue("origins") |
      sl.getValue() = "*" and what = "@CrossOrigin(origins=\"*\")"
    )
  )
}

predicate corsConfigWildcardCredentials(Variable v, string what) {
  v.getType().(RefType).hasQualifiedName("org.springframework.web.cors", "CorsConfiguration") and
  exists(MethodCall origin, MethodCall cred |
    origin.getQualifier() = v.getAnAccess() and
    cred.getQualifier() = v.getAnAccess() and
    (
      origin.getMethod().hasName("addAllowedOriginPattern") and
      origin.getArgument(0).(StringLiteral).getValue() = "*"
      or
      origin.getMethod().hasName("addAllowedOrigin") and
      origin.getArgument(0).(StringLiteral).getValue() = "*"
    ) and
    cred.getMethod().hasName("setAllowCredentials") and
    cred.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
    what = "CorsConfiguration: wildcard origin + setAllowCredentials(true)"
  )
}

from Element e, string msg
where
  exists(Annotation a | crossOriginWildcard(a, msg) and e = a)
  or
  exists(Variable v | corsConfigWildcardCredentials(v, msg) and e = v)
select e, "Permissive CORS: " + msg + "."
