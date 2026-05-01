/**
 * @name Spring open redirect from untrusted input
 * @description User input is used as the target of sendRedirect, RedirectView,
 *              HttpHeaders.setLocation, or returned as `redirect:<tainted>`
 *              from a controller.
 * @kind path-problem
 * @id java/spring/open-redirect
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @tags security
 *       external/cwe/cwe-601
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import OpenRedirectFlow::PathGraph

class RedirectStringReturn extends DataFlow::Node {
  RedirectStringReturn() {
    exists(ReturnStmt rs, AddExpr concatExpr |
      rs.getResult() = concatExpr and
      concatExpr.getLeftOperand().(StringLiteral).getValue().regexpMatch("(?i)redirect:.*") and
      concatExpr.getRightOperand() = this.asExpr()
    )
  }
}

module OpenRedirectConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RedirectSink or sink instanceof RedirectStringReturn
  }
}

module OpenRedirectFlow = TaintTracking::Global<OpenRedirectConfig>;

from OpenRedirectFlow::PathNode source, OpenRedirectFlow::PathNode sink
where OpenRedirectFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Redirect target derived from $@.",
  source.getNode(), "untrusted input"
