import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

class Greeting { public String message; }
class User { public String name; public String role; }
class Employee { public String name; }

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

    // ok: spring-mvc-pojo-parameter-without-requestbody
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

    // v3 triage FP — VisitResource.java:72 shape: @RequestParam("name")
    // List<Integer>. Round-3 fix added the @RequestParam(...) form.
    // ok: spring-mvc-pojo-parameter-without-requestbody
    @GetMapping("/visits")
    public String visits(@RequestParam("petId") List<Integer> petIds) { return ""; }

    // v3 triage FP — StringToEmployeeConverterController.java:13 shape:
    // @RequestParam("name") <CustomConverterType>.
    // ok: spring-mvc-pojo-parameter-without-requestbody
    @GetMapping("/employee")
    public String employee(@RequestParam("employee") Employee employee) { return ""; }

    // v3 triage FP — FileUpload.java:50 shape: @RequestParam("file")
    // MultipartFile. The unannotated MultipartFile exclusion already exists,
    // but with @RequestParam attached the @RequestParam(...) form needs to
    // win first.
    // ok: spring-mvc-pojo-parameter-without-requestbody
    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) { return ""; }
}
