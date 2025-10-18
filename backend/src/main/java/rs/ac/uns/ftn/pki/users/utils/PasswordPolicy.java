package rs.ac.uns.ftn.pki.users.utils;

import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.List;

@Component
public class PasswordPolicy {

    public record Result(boolean ok, List<String> errors) {}

    public Result evaluate(
            String password,
            String email,
            String name,
            String surname,
            ICommonPasswordStore common
    ) {
        List<String> errors = new ArrayList<>();

        if (password == null || password.isBlank()) {
            errors.add("Password is required.");
            return new Result(false, errors);
        }

        if (password.length() < 8) errors.add("Use at least 8 characters.");
        if (password.length() > 64) errors.add("Use up to 64 characters.");

        if (common != null && common.contains(password)) {
            errors.add("This password is too common.");
        }

        return new Result(errors.isEmpty(), errors);
    }
}
