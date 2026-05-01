import org.springframework.web.client.RestTemplate;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@RestController
class T {

    @GetMapping("/fetch")
    void bad(HttpServletRequest req) {
        String url = req.getParameter("u");
        // ruleid: spring-rest-template-default-redirect-policy
        RestTemplate rt = new RestTemplate();
        // ruleid: spring-ssrf-tainted-http-client
        rt.getForObject(url, String.class);
    }

    @GetMapping("/exchange")
    void badExchange(HttpServletRequest req) {
        String url = req.getParameter("u");
        // ruleid: spring-rest-template-default-redirect-policy
        RestTemplate rt = new RestTemplate();
        // ruleid: spring-ssrf-tainted-http-client
        rt.exchange(url, org.springframework.http.HttpMethod.GET, null, String.class);
    }

    // Bench v2 false-positive shape: Map.put(taintedKey, val) used to fire
    // because the sink list included `$RT.put($URL, ...)`. After dropping
    // generic `put`/`delete`/`execute` from the sink list, this no longer
    // matches.
    @GetMapping("/map")
    void okMap(HttpServletRequest req) {
        String key = req.getParameter("k");
        Map<String, String> m = new HashMap<>();
        // ok: spring-ssrf-tainted-http-client
        m.put(key, "value");
    }

    @GetMapping("/static")
    void okStatic() {
        // ruleid: spring-rest-template-default-redirect-policy
        RestTemplate rt = new RestTemplate();
        // ok: spring-ssrf-tainted-http-client
        rt.getForObject("https://trusted.example/api", String.class);
    }
}
