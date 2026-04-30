/**
 * @name Spring SpEL expression built from untrusted input
 * @description Untrusted data flows into SpelExpressionParser.parseExpression
 *              or Expression.getValue/setValue — RCE
 *              (CVE-2017-8046, CVE-2018-1273, CVE-2022-22963).
 * @kind path-problem
 * @id java/spring/spel-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-094
 *       spring
 *       rce
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import SpelInjectionFlow::PathGraph

module SpelInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SpelParseSink }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(MethodAccess ma | ma.getMethod().hasName(["concat", "toString", "format"]) |
      a.asExpr() = ma.getAnArgument() and b.asExpr() = ma
    )
  }
}

module SpelInjectionFlow = TaintTracking::Global<SpelInjectionConfig>;

from SpelInjectionFlow::PathNode source, SpelInjectionFlow::PathNode sink
where SpelInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SpEL expression built from $@.",
  source.getNode(), "untrusted input"
