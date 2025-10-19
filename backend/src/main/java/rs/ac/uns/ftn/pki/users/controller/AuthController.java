package rs.ac.uns.ftn.pki.users.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.pki.users.dtos.requests.LoginRequest;
import rs.ac.uns.ftn.pki.users.dtos.requests.RefreshRequest;
import rs.ac.uns.ftn.pki.users.dtos.responses.LoginResponse;
import rs.ac.uns.ftn.pki.users.dtos.responses.RefreshResponse;
import rs.ac.uns.ftn.pki.users.service.AuthService;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService service;

    public AuthController(AuthService service) {
        this.service = service;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Validated @RequestBody LoginRequest req) {
        var r = service.login(req);
        return ResponseEntity.status(r.status()).body(r.ok() != null ? r.ok() : Map.of("error", r.err()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Validated @RequestBody RefreshRequest req) {
        var r = service.refresh(req);
        return ResponseEntity.status(r.status()).body(r.ok() != null ? r.ok() : Map.of("error", r.err()));
    }

    @PostMapping("/logout/{userId}")
    public ResponseEntity<?> logout(@PathVariable UUID userId) {
        int status = service.logout(userId);
        return ResponseEntity.status(status).build();
    }

    @PostMapping("/logout-all/{userId}")
    public ResponseEntity<?> logoutAll(@PathVariable UUID userId) {
        int status = service.logoutAll(userId);
        return ResponseEntity.status(status).build();
    }
}
