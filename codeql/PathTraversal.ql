/**
 * @name Spring path traversal: untrusted input reaches a Resource/Path/File ctor
 * @description User input flows into the path of FileSystemResource,
 *              PathResource, UrlResource, ResourceLoader.getResource,
 *              Paths.get, or a java.io.File ctor — without normalize() +
 *              startsWith(baseDir). Same shape as CVE-2024-38816 and
 *              the older CVE-2016-9878.
 * @kind path-problem
 * @id java/spring/path-traversal
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import PathTraversalFlow::PathGraph

class NormalizeAndCheckSanitizer extends DataFlow::Node {
  NormalizeAndCheckSanitizer() {
    exists(MethodAccess normalize, MethodAccess startsWith |
      normalize.getMethod().hasName("normalize") and
      normalize.getMethod()
          .getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("java.nio.file", "Path") and
      startsWith.getQualifier() = normalize and
      startsWith.getMethod().hasName("startsWith") and
      this.asExpr() = normalize
    )
  }
}

module PathTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof FileResourceConstructionSink }

  predicate isBarrier(DataFlow::Node node) { node instanceof NormalizeAndCheckSanitizer }
}

module PathTraversalFlow = TaintTracking::Global<PathTraversalConfig>;

from PathTraversalFlow::PathNode source, PathTraversalFlow::PathNode sink
where PathTraversalFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "File/Resource path built from $@ without normalize+startsWith.",
  source.getNode(), "untrusted input"
