// Sinks shared across queries.

import java
import semmle.code.java.dataflow.DataFlow

class SpelParseSink extends DataFlow::Node {
  SpelParseSink() {
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().getASupertype*().hasQualifiedName(
        "org.springframework.expression", "ExpressionParser") and
      m.hasName(["parseExpression", "parseRaw"])
    )
  }
}

class OutgoingHttpUrlSink extends DataFlow::Node {
  OutgoingHttpUrlSink() {
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      // RestTemplate / RestOperations
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.web.client", ["RestTemplate", "RestOperations", "RestClient"]) and
      m.hasName(["getForObject", "getForEntity", "postForObject", "postForEntity",
                 "postForLocation", "put", "delete", "exchange", "execute", "patchForObject"])
    )
    or
    // WebClient / WebClient.RequestBodyUriSpec.uri / RequestHeadersUriSpec.uri
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.web.reactive.function.client",
            ["WebClient", "WebClient$RequestHeadersUriSpec", "WebClient$RequestBodyUriSpec"]) and
      m.hasName("uri")
    )
    or
    // JDK HttpRequest builder
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.net.http", ["HttpRequest", "HttpRequest$Builder"]) and
      m.hasName(["uri", "newBuilder"])
    )
    or
    // OkHttp Request.Builder.url(...)
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and m.hasName("url")
    )
    or
    // Apache HC HttpRequestBase ctors
    exists(ConstructorCall cc | cc.getAnArgument() = this.asExpr() |
      cc.getConstructedType()
          .getASupertype*()
          .hasQualifiedName("org.apache.http.client.methods",
            ["HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpHead", "HttpPatch", "HttpOptions"])
    )
  }
}

class FileResourceConstructionSink extends DataFlow::Node {
  FileResourceConstructionSink() {
    exists(ConstructorCall cc | cc.getAnArgument() = this.asExpr() |
      cc.getConstructedType()
          .hasQualifiedName("org.springframework.core.io",
            ["FileSystemResource", "PathResource", "UrlResource", "ClassPathResource",
              "FileUrlResource"])
    )
    or
    exists(ConstructorCall cc | cc.getAnArgument() = this.asExpr() |
      cc.getConstructedType().hasQualifiedName("java.io", "File")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.springframework.core.io", "ResourceLoader") and
      m.hasName("getResource")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.springframework.util", "ResourceUtils") and
      m.hasName(["getFile", "getURL"])
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.nio.file", ["Paths", "Path"]) and
      m.hasName(["get", "of"])
    )
  }
}

class RedirectSink extends DataFlow::Node {
  RedirectSink() {
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
      m.hasName("sendRedirect")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
      m.hasName("sendRedirect")
    )
    or
    exists(ConstructorCall cc | cc.getAnArgument() = this.asExpr() |
      cc.getConstructedType()
          .hasQualifiedName("org.springframework.web.servlet.view", "RedirectView")
      or
      cc.getConstructedType()
          .hasQualifiedName("org.springframework.web.reactive.result.view", "RedirectView")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
      m.hasName("setLocation")
    )
  }
}

class JndiLookupSink extends DataFlow::Node {
  JndiLookupSink() {
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().getASupertype*().hasQualifiedName("javax.naming", "Context") and
      m.hasName("lookup")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("org.springframework.jndi", "JndiTemplate") and
      m.hasName("lookup")
    )
  }
}

class SqlStringSink extends DataFlow::Node {
  SqlStringSink() {
    exists(MethodCall ma, Method m | ma.getArgument(0) = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("org.springframework.jdbc.core",
            ["JdbcTemplate", "JdbcOperations", "NamedParameterJdbcTemplate", "NamedParameterJdbcOperations"]) and
      m.hasName(["query", "queryForObject", "queryForList", "queryForMap",
                 "queryForRowSet", "update", "execute", "batchUpdate"])
    )
    or
    exists(MethodCall ma, Method m | ma.getArgument(0) = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("javax.persistence", "EntityManager") and
      m.hasName(["createQuery", "createNativeQuery"])
    )
    or
    exists(MethodCall ma, Method m | ma.getArgument(0) = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType()
          .getASupertype*()
          .hasQualifiedName("jakarta.persistence", "EntityManager") and
      m.hasName(["createQuery", "createNativeQuery"])
    )
    or
    exists(MethodCall ma, Method m | ma.getArgument(0) = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().getASupertype*().hasQualifiedName("org.hibernate", "Session") and
      m.hasName(["createQuery", "createNativeQuery", "createSQLQuery"])
    )
  }
}

class ProcessExecSink extends DataFlow::Node {
  ProcessExecSink() {
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and m.hasName("exec")
    )
    or
    exists(ConstructorCall cc | cc.getAnArgument() = this.asExpr() |
      cc.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
    )
    or
    exists(MethodCall ma, Method m | ma.getAnArgument() = this.asExpr() and m = ma.getMethod() |
      m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
      m.hasName("command")
    )
  }
}

predicate isSpringController(Class c) {
  c.getAnAnnotation()
      .getType()
      .hasQualifiedName("org.springframework.stereotype", "Controller")
  or
  c.getAnAnnotation()
      .getType()
      .hasQualifiedName("org.springframework.web.bind.annotation", "RestController")
}

predicate isRequestMappingMethod(Method m) {
  m.getAnAnnotation()
      .getType()
      .hasQualifiedName("org.springframework.web.bind.annotation",
        ["RequestMapping", "GetMapping", "PostMapping", "PutMapping", "PatchMapping",
          "DeleteMapping"])
}
