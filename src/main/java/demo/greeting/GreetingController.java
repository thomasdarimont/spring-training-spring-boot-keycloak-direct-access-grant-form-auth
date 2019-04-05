package demo.greeting;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;

@RestController
class GreetingController {

    @GetMapping("/greet")
    Object greet(Principal principal) {
        return Collections.singletonMap("greeting", String.format("Hello %s", principal.getName()));
    }
}
