import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.persistence.Entity;

class Greeting { public String message; }
class User { public String name; public String role; }

@Entity
class Pet { public Long id; public String name; public String role; }

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

    // Loose rule fires on any capitalised @RequestBody type (LOW confidence,
    // INFO severity since the bench showed lots of plain-DTO false positives).
    // ruleid: spring-jpa-entity-as-controller-parameter
    @PostMapping("/users-rb")
    public String createWithRequestBody(@RequestBody User user) {
        return "ok";
    }

    // Same-file @Entity + @RequestBody.
    //   - loose rule fires (capitalised type name)
    //   - precise rule SHOULD fire but cannot in stable Semgrep
    //     (metavariable-pattern operates on the type-name binding "Pet",
    //     which has no @Entity text in its source range). Marked as
    //     todoruleid to track the gap; will become ruleid when Semgrep Pro
    //     inter-file mode or an equivalent is wired up.
    // todoruleid: spring-jpa-entity-as-controller-parameter-precise
    // ruleid: spring-jpa-entity-as-controller-parameter
    @PostMapping("/pets")
    public String createPet(@RequestBody Pet pet) {
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
