/**
 * @name Spring Security auth patterns prone to bypass
 * @description Two shapes:
 *              (1) RegexRequestMatcher with `.` and no DOTALL — `.` doesn't
 *              match `\n`, so encoded CR/LF in the path bypasses the rule
 *              (CVE-2022-22978-family);
 *              (2) @PreAuthorize / @PostAuthorize / @Secured / @RolesAllowed
 *              on an interface or abstract generic class — Spring may miss
 *              them on parameterised types (CVE-2025-41248, CVE-2025-41249).
 * @kind problem
 * @id java/spring/auth-bypass-patterns
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-863
 *       spring
 */

import java

predicate regexMatcherWithoutDotAll(Expr e, string pattern) {
  exists(ConstructorCall cc, StringLiteral sl |
    cc = e and
    cc.getConstructedType()
        .hasQualifiedName("org.springframework.security.web.util.matcher", "RegexRequestMatcher") and
    sl = cc.getArgument(0) and
    sl.getValue().regexpMatch(".*\\..*") and
    not sl.getValue().regexpMatch("\\(\\?s\\).*") and
    pattern = sl.getValue()
  )
  or
  exists(MethodAccess ma, StringLiteral sl |
    ma = e and
    ma.getMethod()
        .getDeclaringType()
        .hasQualifiedName("org.springframework.security.web.util.matcher", "RegexRequestMatcher") and
    ma.getMethod().hasName("regexMatcher") and
    sl = ma.getArgument(0) and
    sl.getValue().regexpMatch(".*\\..*") and
    not sl.getValue().regexpMatch("\\(\\?s\\).*") and
    pattern = sl.getValue()
  )
}

predicate methodSecurityOnInterfaceOrAbstract(Method m, string ann) {
  (m.getDeclaringType() instanceof Interface or m.getDeclaringType().isAbstract()) and
  exists(Annotation a | a = m.getAnAnnotation() |
    (
      a.getType().hasQualifiedName("org.springframework.security.access.prepost", ["PreAuthorize", "PostAuthorize"])
      or
      a.getType().hasQualifiedName("org.springframework.security.access.annotation", "Secured")
      or
      a.getType().hasQualifiedName("javax.annotation.security", "RolesAllowed")
      or
      a.getType().hasQualifiedName("jakarta.annotation.security", "RolesAllowed")
    ) and
    ann = a.getType().getName()
  )
}

from Element e, string msg
where
  exists(string pat |
    regexMatcherWithoutDotAll(e, pat) and
    msg =
      "RegexRequestMatcher \"" + pat + "\" has '.' without (?s). CR/LF bypass (CVE-2022-22978)."
  )
  or
  exists(string ann |
    methodSecurityOnInterfaceOrAbstract(e, ann) and
    msg = "@" + ann + " on interface/abstract may not be detected on the impl (CVE-2025-41248/41249)."
  )
select e, msg
