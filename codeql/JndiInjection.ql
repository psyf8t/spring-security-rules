/**
 * @name JNDI lookup with untrusted name
 * @description User input flows into Context.lookup / JndiTemplate.lookup —
 *              Log4Shell-class RCE on JREs that haven't disabled remote
 *              codebase trust.
 * @kind path-problem
 * @id java/spring/jndi-injection
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-074
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import JndiFlow::PathGraph

module JndiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof JndiLookupSink }
}

module JndiFlow = TaintTracking::Global<JndiConfig>;

from JndiFlow::PathNode source, JndiFlow::PathNode sink
where JndiFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "JNDI lookup of $@.",
  source.getNode(), "untrusted name"
