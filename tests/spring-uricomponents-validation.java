import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

class T {
    boolean badInline(String url) {
        // ruleid: spring-uricomponents-host-validation-pattern
        return "trusted.example".equals(UriComponentsBuilder.fromUriString(url).build().getHost());
    }

    boolean badViaVar(String url) {
        UriComponents uri = UriComponentsBuilder.fromUriString(url).build();
        // ruleid: spring-uricomponents-host-validation-pattern
        return "trusted.example".equals(uri.getHost());
    }

    boolean ok(String url) {
        // ok: spring-uricomponents-host-validation-pattern
        return java.net.URI.create(url).getHost().equals("trusted.example");
    }
}
