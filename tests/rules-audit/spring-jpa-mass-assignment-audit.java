import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import javax.persistence.Entity;

class User { public String name; public String role; }

@Entity
class Pet { public Long id; public String name; public String role; }

@RestController
class T {
    // Loose rule fires on any capitalised @RequestBody type.
    // ruleid: spring-jpa-entity-as-controller-parameter
    @PostMapping("/users")
    public String createUser(@RequestBody User user) {
        return "ok";
    }

    // Same-file @Entity + @RequestBody.
    //   - loose rule fires (capitalised type)
    //   - precise rule SHOULD fire but cannot in stable Semgrep
    //     (metavariable-pattern operates on the type-name binding "Pet",
    //     which has no @Entity text in its source range). Tracked as
    //     todoruleid until cross-file resolution is wired up.
    // todoruleid: spring-jpa-entity-as-controller-parameter-precise
    // ruleid: spring-jpa-entity-as-controller-parameter
    @PostMapping("/pets")
    public String createPet(@RequestBody Pet pet) {
        return "ok";
    }

    // Lowercase type name → loose regex doesn't match → neither audit rule fires.
    // ok: spring-jpa-entity-as-controller-parameter
    @PostMapping("/blob")
    public String createBlob(@RequestBody java.util.Map<String, Object> blob) {
        return "ok";
    }
}
