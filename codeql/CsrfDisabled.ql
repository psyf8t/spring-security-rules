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

class CsrfDisableCall extends MethodAccess {
  CsrfDisableCall() {
    // http.csrf().disable()
    exists(MethodAccess csrf |
      csrf.getMethod().hasName("csrf") and
      csrf.getMethod()
          .getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.security.config.annotation.web.builders",
            ["HttpSecurity", "WebSecurity"]) and
      this.getQualifier() = csrf and
      this.getMethod().hasName("disable")
    )
    or
    // http.csrf(c -> c.disable())
    exists(LambdaExpr le |
      le.getEnclosingCallable() = this.getEnclosingCallable() and
      le.getAParameter()
          .getType()
          .(RefType)
          .getASupertype*()
          .hasQualifiedName("org.springframework.security.config.annotation.web.configurers",
            "CsrfConfigurer") and
      this.getMethod().hasName("disable") and
      this.getEnclosingStmt().getEnclosingStmt*() = le.getExprBody().(Stmt)
    )
  }
}

from CsrfDisableCall c
select c, "CSRF protection disabled."
