import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;

class Greeting { public String message; }
class User { public String name; public String role; }

@Controller
class HelloController {
    // ruleid: spring-mvc-pojo-parameter-without-requestbody
    @PostMapping("/greeting")
    public String greetingSubmit(@ModelAttribute Greeting greeting, Model model) {
        return "hello";
    }

    // ruleid: spring-mvc-pojo-parameter-without-requestbody
    @PostMapping("/users")
    public String createBare(User user) {
        return "ok";
    }

    // Defect 3 will narrow spring-jpa-entity-as-controller-parameter so the
    // loose rule no longer fires on plain DTOs. Until then it does fire on
    // capitalised type names, which is how the bench surfaced it.
    // ruleid: spring-jpa-entity-as-controller-parameter
    @PostMapping("/users-rb")
    public String createWithRequestBody(@RequestBody User user) {
        return "ok";
    }

    // ok: spring-mvc-pojo-parameter-without-requestbody
    @GetMapping("/users/{id}")
    public String getById(@PathVariable Integer id) {
        return "ok";
    }

    // ok: spring-mvc-pojo-parameter-without-requestbody
    @GetMapping("/echo")
    public String echo(@RequestParam String name) {
        return name;
    }

    // ok: spring-mvc-pojo-parameter-without-requestbody
    @GetMapping("/req")
    public String req(HttpServletRequest request) {
        return "ok";
    }
}
