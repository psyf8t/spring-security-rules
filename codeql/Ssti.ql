/**
 * @name Spring server-side template injection
 * @description User input either flows back as a controller view name, or
 *              into the first arg of TemplateEngine.process / processString.
 *              If the value is a template *string* this is full SSTI; if
 *              it's a name, the attacker picks any template the engine
 *              can resolve.
 * @kind path-problem
 * @id java/spring/ssti
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-1336
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import SstiFlow::PathGraph

class TemplateEngineSink extends DataFlow::Node {
  TemplateEngineSink() {
    exists(MethodAccess ma | ma.getArgument(0) = this.asExpr() |
      ma.getMethod()
          .getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.thymeleaf", ["ITemplateEngine", "TemplateEngine"]) and
      ma.getMethod().hasName(["process", "processString"])
      or
      ma.getMethod()
          .getDeclaringType()
          .hasQualifiedName("freemarker.template", "Configuration") and
      ma.getMethod().hasName("getTemplate")
    )
  }
}

class ControllerStringReturnSink extends DataFlow::Node {
  ControllerStringReturnSink() {
    exists(ReturnStmt rs, Method m |
      rs.getResult() = this.asExpr() and
      m = rs.getEnclosingCallable() and
      isSpringController(m.getDeclaringType()) and
      isRequestMappingMethod(m) and
      m.getReturnType().(RefType).hasQualifiedName("java.lang", "String")
    )
  }
}

module SstiConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof TemplateEngineSink or sink instanceof ControllerStringReturnSink
  }
}

module SstiFlow = TaintTracking::Global<SstiConfig>;

from SstiFlow::PathNode source, SstiFlow::PathNode sink
where SstiFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Template/view name from $@.",
  source.getNode(), "untrusted input"
