package rs.ac.uns.ftn.pki.users.controller;
import rs.ac.uns.ftn.pki.users.dtos.requests.RegisterRequest;
import rs.ac.uns.ftn.pki.users.dtos.responses.RegistrationResult;
import rs.ac.uns.ftn.pki.users.service.RegistrationService;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    private final RegistrationService service;

    public RegistrationController(RegistrationService service) {
        this.service = service;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Validated @RequestBody RegisterRequest req) {
        RegistrationResult result = service.register(req, false);
        return ResponseEntity.status(result.getStatusCode()).body(result.getResponse());
    }

    @PostMapping("/register/ca")
    public ResponseEntity<?> registerCa(@Validated @RequestBody RegisterRequest req) {
        RegistrationResult result = service.register(req, true);
        return ResponseEntity.status(result.getStatusCode()).body(result.getResponse());
    }
}
