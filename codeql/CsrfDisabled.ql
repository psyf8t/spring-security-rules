/**
 * @name Spring Security CSRF protection is disabled
 * @description `http.csrf().disable()` (or its lambda variants). Acceptable
 *              for stateless REST with Authorization-header tokens; broken
 *              for cookie sessions.
 * @kind problem
 * @id java/spring/csrf-disabled
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-352
 *       spring
 */

import java

// Matches the chained `http.csrf().disable()` shape and the method-reference
// `http.csrf(AbstractHttpConfigurer::disable)` shape. The lambda body
// variant `http.csrf(c -> c.disable())` is left to Semgrep — modelling
// "any disable() call whose receiver type is CsrfConfigurer" cleanly in
// CodeQL needs more setup than this single-file query is worth.
class CsrfDisableCall extends MethodCall {
  CsrfDisableCall() {
    exists(MethodCall csrf |
      csrf.getMethod().hasName("csrf") and
      csrf.getMethod()
          .getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.security.config.annotation.web.builders",
            ["HttpSecurity", "WebSecurity"]) and
      this.getQualifier() = csrf and
      this.getMethod().hasName("disable")
    )
  }
}

class CsrfDisableMethodRef extends MethodCall {
  CsrfDisableMethodRef() {
    this.getMethod().hasName("csrf") and
    this.getMethod()
        .getDeclaringType()
        .getASupertype*()
        .hasQualifiedName("org.springframework.security.config.annotation.web.builders",
          ["HttpSecurity", "WebSecurity"]) and
    this.getAnArgument().toString().regexpMatch(".*disable.*")
  }
}

from Call c
where c instanceof CsrfDisableCall or c instanceof CsrfDisableMethodRef
select c, "CSRF protection disabled."
