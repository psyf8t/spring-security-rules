/**
 * @name Spring SSRF: untrusted URL flows into outgoing HTTP client
 * @description User input is used as the URL/URI of an outgoing HTTP call
 *              (RestTemplate, WebClient, RestClient, JDK HttpClient, OkHttp,
 *              Apache HC). Allowlist hosts and pre-resolve DNS.
 * @kind path-problem
 * @id java/spring/ssrf
 * @problem.severity error
 * @security-severity 8.6
 * @precision high
 * @tags security
 *       external/cwe/cwe-918
 *       spring
 *       ssrf
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import SsrfFlow::PathGraph

module SsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof OutgoingHttpUrlSink }

  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.net", ["URI", "URL"]) and
      cc.getAnArgument() = a.asExpr() and
      b.asExpr() = cc
    )
    or
    exists(MethodCall ma |
      ma.getMethod().hasName("create") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URI") and
      ma.getAnArgument() = a.asExpr() and
      b.asExpr() = ma
    )
    or
    // UriComponentsBuilder.fromUriString(...).build().toUri()
    exists(MethodCall fromUri, MethodCall build, MethodCall toUri |
      fromUri.getMethod().hasName(["fromUriString", "fromHttpUrl"]) and
      fromUri.getAnArgument() = a.asExpr() and
      build.getQualifier() = fromUri and
      build.getMethod().hasName("build") and
      toUri.getQualifier() = build and
      toUri.getMethod().hasName("toUri") and
      b.asExpr() = toUri
    )
  }
}

module SsrfFlow = TaintTracking::Global<SsrfConfig>;

from SsrfFlow::PathNode source, SsrfFlow::PathNode sink
where SsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Outgoing HTTP request uses URL from $@.",
  source.getNode(), "untrusted input"
