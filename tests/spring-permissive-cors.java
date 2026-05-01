import org.springframework.web.bind.annotation.*;

@RestController
class T {
    // ruleid: spring-crossorigin-wildcard
    @CrossOrigin(origins = "*")
    @GetMapping("/a")
    public String bad1() { return ""; }

    // ruleid: spring-crossorigin-wildcard
    @CrossOrigin("*")
    @GetMapping("/b")
    public String bad2() { return ""; }

    // ruleid: spring-crossorigin-wildcard
    @CrossOrigin
    @GetMapping("/c")
    public String bad3() { return ""; }

    // ok: spring-crossorigin-wildcard
    @CrossOrigin(origins = "https://trusted.example")
    @GetMapping("/d")
    public String okExplicit() { return ""; }
}
