/**
 * @name Cookie / ResponseCookie missing Secure or HttpOnly
 * @description A javax.servlet.http.Cookie (or Spring ResponseCookie) is
 *              built without setSecure(true) / setHttpOnly(true) (resp.
 *              .secure(true).httpOnly(true)).
 * @kind problem
 * @id java/spring/insecure-cookie
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-1004
 *       spring
 */

import java

predicate cookieMissingFlags(Variable v, string what) {
  v.getType().(RefType).hasQualifiedName(["javax.servlet.http", "jakarta.servlet.http"], "Cookie") and
  not exists(MethodCall m |
    m.getQualifier() = v.getAnAccess() and m.getMethod().hasName("setSecure") and
    m.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  ) and
  not exists(MethodCall m |
    m.getQualifier() = v.getAnAccess() and m.getMethod().hasName("setHttpOnly") and
    m.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  ) and
  what = "Cookie missing setSecure(true) and/or setHttpOnly(true)"
}

predicate responseCookieMissingFlags(MethodCall from_, string what) {
  from_.getMethod().getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseCookie") and
  from_.getMethod().hasName("from") and
  not exists(MethodCall sec |
    sec.getQualifier+() = from_ and sec.getMethod().hasName("secure") and
    sec.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  ) and
  not exists(MethodCall ho |
    ho.getQualifier+() = from_ and ho.getMethod().hasName("httpOnly") and
    ho.getArgument(0).(BooleanLiteral).getBooleanValue() = true
  ) and
  what = "ResponseCookie.from(...) without .secure(true).httpOnly(true)"
}

from Element e, string what
where
  exists(Variable v | cookieMissingFlags(v, what) and e = v)
  or
  exists(MethodCall m | responseCookieMissingFlags(m, what) and e = m)
select e, what + "."
