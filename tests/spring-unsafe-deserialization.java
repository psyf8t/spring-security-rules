import org.springframework.context.annotation.Bean;
import org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter;
import org.springframework.remoting.rmi.RmiServiceExporter;
import com.fasterxml.jackson.databind.ObjectMapper;

class Cfg {
    // ruleid: spring-httpinvoker-exporter-bean
    @Bean
    public HttpInvokerServiceExporter http() {
        // ruleid: spring-httpinvoker-exporter-bean
        return new HttpInvokerServiceExporter();
    }

    // ruleid: spring-httpinvoker-exporter-bean
    @Bean
    public RmiServiceExporter rmi() {
        // ruleid: spring-httpinvoker-exporter-bean
        return new RmiServiceExporter();
    }

    @Bean
    // ok: spring-httpinvoker-exporter-bean
    public String unrelated() { return "ok"; }

    void badJacksonDefaultTyping(ObjectMapper m) {
        // ruleid: spring-jackson-default-typing-enabled
        m.enableDefaultTyping();
    }
}
