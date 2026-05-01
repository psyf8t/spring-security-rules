import org.springframework.context.annotation.Bean;
import org.springframework.cloud.function.context.config.RoutingFunction;

class Cfg {
    // ruleid: spring-cloud-function-routing-function
    @Bean
    public RoutingFunction routing() {
        return null;
    }

    // ok: spring-cloud-function-routing-function
    @Bean
    public String unrelated() {
        return "ok";
    }
}
