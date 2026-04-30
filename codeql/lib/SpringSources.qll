// Spring-aware RemoteFlowSource subclasses: controller params, WebFlux
// ServerHttpRequest, STOMP messages. Pulls in stdlib FlowSources so queries
// get both with a single import.

import java
import semmle.code.java.dataflow.FlowSources

class SpringControllerInputParameter extends RemoteFlowSource {
  SpringControllerInputParameter() {
    exists(Parameter p, Annotation a |
      this.asParameter() = p and
      a = p.getAnAnnotation() and
      a.getType()
          .hasQualifiedName("org.springframework.web.bind.annotation",
            ["RequestParam", "PathVariable", "RequestHeader", "RequestBody",
              "ModelAttribute", "CookieValue", "MatrixVariable"])
    )
  }

  override string getSourceType() { result = "Spring controller input" }
}

class SpringWebFluxRequestSource extends RemoteFlowSource {
  SpringWebFluxRequestSource() {
    exists(MethodAccess ma, Method m | ma = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().getASupertype*().hasQualifiedName(
        "org.springframework.http.server.reactive", "ServerHttpRequest") and
      m.hasName(["getQueryParams", "getHeaders", "getPath", "getURI", "getCookies",
                 "getRemoteAddress"])
    )
  }

  override string getSourceType() { result = "Spring WebFlux request" }
}

class StompMessageSource extends RemoteFlowSource {
  StompMessageSource() {
    exists(MethodAccess ma, Method m | ma = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.messaging.simp.stomp", "StompHeaderAccessor") and
      m.hasName(["getFirstNativeHeader", "getNativeHeader", "getDestination", "getMessage"])
    )
    or
    exists(MethodAccess ma, Method m | ma = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.springframework.messaging", "Message") and
      m.hasName(["getPayload", "getHeaders"])
    )
  }

  override string getSourceType() { result = "Spring STOMP message" }
}
