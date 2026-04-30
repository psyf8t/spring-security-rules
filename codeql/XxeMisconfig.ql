/**
 * @name Insecure XML parser configuration
 * @description JAXP factories left at defaults, or
 *              Jaxb2Marshaller.setProcessExternalEntities(true) /
 *              setSupportDtd(true) — XXE.
 * @kind problem
 * @id java/spring/xxe-misconfig
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       external/cwe/cwe-611
 *       spring
 */

import java

predicate jaxb2DangerousSetter(MethodAccess ma, string what) {
  ma.getMethod().getDeclaringType().hasQualifiedName(
    "org.springframework.oxm.jaxb", "Jaxb2Marshaller") and
  ma.getMethod().hasName(["setProcessExternalEntities", "setSupportDtd"]) and
  ma.getArgument(0).(BooleanLiteral).getBooleanValue() = true and
  what = ma.getMethod().getName() + "(true)"
}

predicate factoryUsedWithoutHardening(MethodAccess factory, string what) {
  factory.getMethod().hasName("newInstance") and
  factory.getMethod()
      .getDeclaringType()
      .hasQualifiedName("javax.xml.parsers",
        ["DocumentBuilderFactory", "SAXParserFactory"]) and
  not exists(MethodAccess hardening |
    hardening.getQualifier+() = factory or hardening.getQualifier() = factory.getEnclosingStmt().(LocalVariableDeclStmt).getAVariable().getAnAccess() |
    hardening.getMethod().hasName("setFeature") and
    hardening.getArgument(0).(StringLiteral).getValue() = "http://apache.org/xml/features/disallow-doctype-decl" and
    hardening.getArgument(1).(BooleanLiteral).getBooleanValue() = true
  ) and
  what = factory.getMethod().getDeclaringType().getName() + ".newInstance() without disallow-doctype-decl"
}

predicate xmlInputFactoryUnhardened(MethodAccess factory, string what) {
  factory.getMethod().hasName("newInstance") and
  factory.getMethod().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory") and
  not exists(MethodAccess set |
    set.getMethod().hasName("setProperty") and
    set.getQualifier() = factory.getEnclosingStmt().(LocalVariableDeclStmt).getAVariable().getAnAccess() and
    set.getArgument(0).toString().regexpMatch(".*SUPPORT_DTD.*") and
    set.getArgument(1).(BooleanLiteral).getBooleanValue() = false
  ) and
  what = "XMLInputFactory.newInstance() without disabling DTD"
}

from Element e, string what
where
  exists(MethodAccess ma | jaxb2DangerousSetter(ma, what) and e = ma)
  or
  exists(MethodAccess ma | factoryUsedWithoutHardening(ma, what) and e = ma)
  or
  exists(MethodAccess ma | xmlInputFactoryUnhardened(ma, what) and e = ma)
select e, "XXE risk: " + what + "."
