package rs.ac.uns.ftn.pki.users.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.pki.users.dtos.requests.LoginRequest;
import rs.ac.uns.ftn.pki.users.dtos.requests.RefreshRequest;
import rs.ac.uns.ftn.pki.users.dtos.responses.LoginResponse;
import rs.ac.uns.ftn.pki.users.dtos.responses.RefreshResponse;
import rs.ac.uns.ftn.pki.users.model.User;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;
import rs.ac.uns.ftn.pki.users.utils.JwtProvider;
import rs.ac.uns.ftn.pki.users.utils.TokenUtils;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    public record ServiceResult<T>(T ok, int status, String err) {}

    private final UserRepository users;
    private final JwtProvider jwt;

    // config
    private final String issuer;
    private final String audience;
    private final int accessMinutes;
    private final int refreshTtlDays;

    public AuthService(
            UserRepository users,
            JwtProvider jwt,
            @Value("${auth.jwt.issuer}") String issuer,
            @Value("${auth.jwt.audience}") String audience,
            @Value("${auth.jwt.access-minutes:1}") int accessMinutes,
            @Value("${auth.refresh.ttl-days:14}") int refreshTtlDays
    ) {
        this.users = users;
        this.jwt = jwt;
        this.issuer = issuer;
        this.audience = audience;
        this.accessMinutes = accessMinutes;
        this.refreshTtlDays = refreshTtlDays;
    }

    public ServiceResult<LoginResponse> login(LoginRequest req) {
        User u = users.findByEmail(req.getEmail());
        if (u == null) return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), "Invalid credentials");

        if (!Boolean.TRUE.equals(u.getEmailConfirmed()))
            return new ServiceResult<>(null, HttpStatus.FORBIDDEN.value(), "Email not confirmed");

        if (!BCrypt.checkpw(req.getPassword(), u.getHashedPassword()))
            return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), "Invalid credentials");

        var access = jwt.issueAccess(u, issuer, audience, accessMinutes);
        var refresh = rotateNewRefresh(u);

        LoginResponse resp = new LoginResponse(
                access.jwt(), access.exp(),
                refresh.jwt(), refresh.exp(),
                u.getId().toString(),
                u.getRole().name(),
                u.getName(),
                u.getSurname()
        );
        return new ServiceResult<>(resp, HttpStatus.OK.value(), null);
    }

    public ServiceResult<RefreshResponse> refresh(RefreshRequest req) {
        if (req.getRefreshToken() == null || req.getRefreshToken().isBlank())
            return new ServiceResult<>(null, HttpStatus.BAD_REQUEST.value(), "Missing refresh token");

        var v = jwt.validateRefresh(req.getRefreshToken(), issuer, audience);
        if (!v.ok()) return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), v.reason());

        UUID userId = v.userId();
        Optional<User> ou = users.findById(userId);
        if (ou.isEmpty()) return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), "Invalid refresh token");

        User u = ou.get();

        boolean hasStored = u.getRefreshToken() != null &&
                !u.getRefreshToken().isBlank() &&
                u.getRefreshTokenExpiresAt() != null &&
                u.getRefreshTokenExpiresAt().isAfter(OffsetDateTime.now());

        if (!hasStored) return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), "Refresh token revoked");

        String presentedHash = TokenUtils.sha256Hex(req.getRefreshToken().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        if (!presentedHash.equals(u.getRefreshToken())) {
            // revoke on mismatch
            u.setRefreshToken("");
            u.setRefreshTokenExpiresAt(null);
            users.save(u);
            return new ServiceResult<>(null, HttpStatus.UNAUTHORIZED.value(), "Refresh token mismatch; revoked");
        }

        var access = jwt.issueAccess(u, issuer, audience, accessMinutes);
        var refresh = rotateNewRefresh(u);

        RefreshResponse resp = new RefreshResponse(
                access.jwt(), access.exp(),
                refresh.jwt(), refresh.exp(),
                u.getId().toString()
        );
        return new ServiceResult<>(resp, HttpStatus.OK.value(), null);
    }

    public int logout(UUID userId) {
        Optional<User> ou = users.findById(userId);
        if (ou.isPresent()) {
            User u = ou.get();
            u.setRefreshToken("");
            u.setRefreshTokenExpiresAt(null);
            users.save(u);
        }
        return HttpStatus.NO_CONTENT.value();
    }

    public int logoutAll(UUID userId) {
        return logout(userId);
    }

    private JwtProvider.TokenResult rotateNewRefresh(User u) {
        var refresh = jwt.issueRefresh(u, issuer, audience, refreshTtlDays);
        String hashHex = TokenUtils.sha256Hex(refresh.jwt().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        u.setRefreshToken(hashHex);
        u.setRefreshTokenExpiresAt(refresh.exp());
        users.save(u);
        return refresh;
    }
}
