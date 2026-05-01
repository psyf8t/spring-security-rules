import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class Cfg {
    void badMixed(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> {
            // ruleid: spring-security-mixed-mvc-ant-matchers
            a.antMatchers("/admin/**").hasRole("ADMIN");
            a.mvcMatchers("/api/**").authenticated();
        });
    }

    void okConsistent(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> {
            // ok: spring-security-mixed-mvc-ant-matchers
            a.mvcMatchers("/admin/**").hasRole("ADMIN");
            a.mvcMatchers("/api/**").authenticated();
        });
    }
}
