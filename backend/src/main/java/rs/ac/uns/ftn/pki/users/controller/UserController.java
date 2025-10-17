package rs.ac.uns.ftn.pki.users.controller;

import rs.ac.uns.ftn.pki.users.dtos.responses.CaUserResponse;
import rs.ac.uns.ftn.pki.users.service.UserService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService service;

    public UserController(UserService service) {
        this.service = service;
    }

    @GetMapping("/ca")
    public List<CaUserResponse> getAllCaUsers() {
        return service.getAllCaUsers();
    }

    @GetMapping("/ca/valid")
    public List<CaUserResponse> getValidCaUsers() {
        return service.getValidCaUsers();
    }
}
