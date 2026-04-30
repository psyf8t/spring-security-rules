/**
 * @name Command injection via Runtime.exec / ProcessBuilder
 * @description User input flows into Runtime.exec(...), new ProcessBuilder(...)
 *              or ProcessBuilder.command(...).
 * @kind path-problem
 * @id java/spring/command-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import ExecFlow::PathGraph

module ExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof ProcessExecSink }
}

module ExecFlow = TaintTracking::Global<ExecConfig>;

from ExecFlow::PathNode source, ExecFlow::PathNode sink
where ExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Process exec argument from $@.",
  source.getNode(), "untrusted input"
