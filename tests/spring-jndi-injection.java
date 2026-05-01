import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQueryBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.naming.InitialContext;

class T {
    LdapTemplate lt;

    void badLdapConcat(HttpServletRequest req) {
        String login = req.getParameter("u");
        // ruleid: spring-ldap-filter-concat
        lt.search("ou=users", "(uid=" + login + ")", null);
    }

    void badLdapQueryBuilderConcat(HttpServletRequest req) {
        String login = req.getParameter("u");
        // ruleid: spring-ldap-filter-concat
        lt.find(LdapQueryBuilder.query().filter("(uid=" + login + ")"), Object.class);
    }

    void okLdapWhere(HttpServletRequest req) {
        String login = req.getParameter("u");
        // ok: spring-ldap-filter-concat
        lt.find(LdapQueryBuilder.query().where("uid").is(login), Object.class);
    }

    void badJndiLookup(HttpServletRequest req) throws Exception {
        // ruleid: spring-jndi-lookup-tainted
        new InitialContext().lookup(req.getParameter("name"));
    }
}
