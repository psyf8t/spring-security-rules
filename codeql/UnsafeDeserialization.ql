/**
 * @name Spring exposes deserialization-based remote endpoint
 * @description HttpInvoker / Hessian / Burlap / Rmi / JmsInvoker exporter
 *              beans accept Java-serialised payloads from the network
 *              (CVE-2016-1000027 family). Also flags Jackson default typing
 *              and ObjectInputStream wrapping an HTTP request body.
 * @kind problem
 * @id java/spring/unsafe-deserialization
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-502
 *       spring
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

class DangerousExporterType extends Class {
  DangerousExporterType() {
    this.hasQualifiedName("org.springframework.remoting.httpinvoker",
        ["HttpInvokerServiceExporter", "SimpleHttpInvokerServiceExporter"])
    or
    this.hasQualifiedName("org.springframework.remoting.caucho",
        ["HessianServiceExporter", "BurlapServiceExporter"])
    or
    this.hasQualifiedName("org.springframework.remoting.rmi", "RmiServiceExporter")
    or
    this.hasQualifiedName("org.springframework.jms.remoting", "JmsInvokerServiceExporter")
  }
}

predicate exporterDeclaration(Element e, string what) {
  exists(ConstructorCall cc | cc = e |
    cc.getConstructedType() instanceof DangerousExporterType and
    what = "constructor call to " + cc.getConstructedType().getName()
  )
  or
  exists(Method m, Annotation a |
    m = e and
    a = m.getAnAnnotation() and
    a.getType().hasQualifiedName("org.springframework.context.annotation", "Bean") and
    m.getReturnType() instanceof DangerousExporterType and
    what = "@Bean returning " + m.getReturnType().(Class).getName()
  )
}

predicate jacksonDefaultTyping(MethodAccess ma, string what) {
  ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
  ma.getMethod().hasName(["enableDefaultTyping", "activateDefaultTyping", "activateDefaultTypingAsProperty"]) and
  what = "ObjectMapper." + ma.getMethod().getName() + "(...)"
}

predicate ois_from_http(ConstructorCall cc, string what) {
  cc.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream") and
  exists(DataFlow::Node src, DataFlow::Node sink |
    src instanceof RemoteFlowSource and
    sink.asExpr() = cc.getAnArgument() and
    DataFlow::localFlow(src, sink)
  ) and
  what = "ObjectInputStream constructed from request body"
}

from Element e, string what
where
  exporterDeclaration(e, what) or
  exists(MethodAccess ma | jacksonDefaultTyping(ma, what) and e = ma) or
  exists(ConstructorCall cc | ois_from_http(cc, what) and e = cc)
select e, "Unsafe deserialization surface: " + what + "."
