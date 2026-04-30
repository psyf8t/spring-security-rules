/**
 * @name UriComponentsBuilder used for host validation
 * @description Spring's UriComponentsBuilder parses the userinfo segment
 *              differently from most URL libs. When a parsed URL is
 *              host-validated and then sent (CVE-2024-22243 / 22259 / 22262)
 *              the validation can pass while the request lands elsewhere.
 * @kind problem
 * @id java/spring/uricomponents-host-validation
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-918
 *       spring
 */

import java
import semmle.code.java.dataflow.DataFlow

class UriComponentsBuilderFromString extends MethodAccess {
  UriComponentsBuilderFromString() {
    this.getMethod()
        .getDeclaringType()
        .hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    this.getMethod().hasName(["fromUriString", "fromHttpUrl"])
  }
}

class HostAccessor extends MethodAccess {
  HostAccessor() {
    this.getMethod()
        .getDeclaringType()
        .hasQualifiedName("org.springframework.web.util", ["UriComponents", "UriComponentsBuilder"]) and
    this.getMethod().hasName(["getHost", "getAuthority", "toUriString"])
  }
}

predicate hostAccessedAfterParse(UriComponentsBuilderFromString parse, HostAccessor host) {
  exists(DataFlow::Node srcN, DataFlow::Node sinkN |
    srcN.asExpr() = parse and
    sinkN.asExpr() = host.getQualifier() and
    DataFlow::localFlow(srcN, sinkN)
  )
}

from UriComponentsBuilderFromString parse, HostAccessor host
where hostAccessedAfterParse(parse, host)
select parse,
  "URL parsed by UriComponentsBuilder is host-checked via $@ — CVE-2024-22243 shape.",
  host, "host"
