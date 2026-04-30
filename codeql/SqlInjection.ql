/**
 * @name Spring SQL/JPQL injection
 * @description User input flows into the SQL/JPQL string of JdbcTemplate,
 *              EntityManager.createQuery / createNativeQuery, or Hibernate
 *              Session.createQuery / createNativeQuery / createSQLQuery.
 * @kind path-problem
 * @id java/spring/sql-injection
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       spring
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import lib.SpringSources
import lib.SpringSinks
import SqlFlow::PathGraph

module SqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlStringSink }
}

module SqlFlow = TaintTracking::Global<SqlConfig>;

from SqlFlow::PathNode source, SqlFlow::PathNode sink
where SqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Query string built from $@.",
  source.getNode(), "untrusted input"
