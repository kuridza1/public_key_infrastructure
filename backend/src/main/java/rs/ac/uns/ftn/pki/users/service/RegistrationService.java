package rs.ac.uns.ftn.pki.users.service;

import rs.ac.uns.ftn.pki.users.repository.UserRepository;
import rs.ac.uns.ftn.pki.users.repository.VerificationTokenRepository;
import rs.ac.uns.ftn.pki.users.model.*;
import rs.ac.uns.ftn.pki.users.dtos.requests.RegisterRequest;
import rs.ac.uns.ftn.pki.users.dtos.responses.RegistrationResult;
import rs.ac.uns.ftn.pki.users.dtos.responses.RegisterResponse;
import rs.ac.uns.ftn.pki.users.utils.ICommonPasswordStore;
import rs.ac.uns.ftn.pki.users.utils.PasswordPolicy;
import rs.ac.uns.ftn.pki.users.utils.SmtpEmailSender;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.HexFormat;

@Service
public class RegistrationService {

    private final UserRepository userRepo;
    private final VerificationTokenRepository tokenRepo;
    private final SmtpEmailSender emailSender;
    private final PasswordPolicy policy;
    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);
    private final ICommonPasswordStore commonStore;

    @Value("${auth.email-confirmation.token-ttl-minutes:60}")
    private int tokenTtlMinutes;

    @Value("${app.public-base-url:https://localhost:4200}")
    private String publicBaseUrl;

    public RegistrationService(
            UserRepository userRepo,
            VerificationTokenRepository tokenRepo,
            SmtpEmailSender emailSender,
            PasswordPolicy policy,
            ICommonPasswordStore commonStore

    ) {
        this.userRepo = userRepo;
        this.tokenRepo = tokenRepo;
        this.emailSender = emailSender;
        this.policy = policy;
        this.commonStore = commonStore;
    }

    @Transactional
    public RegistrationResult register(RegisterRequest req, boolean creatingCaUser) {
        final String emailNorm = req.getEmail() == null ? "" : req.getEmail().trim();

        if (emailNorm.isBlank() || !emailNorm.contains("@"))
            return new RegistrationResult(false, 400, msg("Invalid email format."));

        if (userRepo.existsByEmail(emailNorm))
            return new RegistrationResult(false, 409, msg("An account with this email already exists."));

        if (!creatingCaUser) {
            if (req.getPassword() == null || !req.getPassword().equals(req.getConfirmPassword()))
                return new RegistrationResult(false, 400, msg("Passwords do not match."));
            var res = policy.evaluate(req.getPassword(), emailNorm, req.getName(), req.getSurname(), commonStore);
            if (!res.ok())
                return new RegistrationResult(false, 400, msg("Weak password. " + String.join(" ", res.errors())));
        }

        final String pwdHash = bcrypt.encode(req.getPassword());

        User user = new User();
        user.setRole(creatingCaUser ? Role.CaUser : Role.EeUser);
        user.setName(blankToNull(req.getName()));
        user.setSurname(blankToNull(req.getSurname()));
        user.setOrganization(blankToNull(req.getOrganization()));
        user.setEmail(emailNorm);
        user.setEmailConfirmed(creatingCaUser);
        user.setHashedPassword(pwdHash);
        user.setRefreshToken("");
        user.setMyCertificates(java.util.Collections.emptyList());
        userRepo.save(user);

        // email confirmation token
        final String tokenPlain = hexRandom(32);
        final String tokenHashHex = sha256Hex(tokenPlain);

        VerificationToken vt = new VerificationToken();
        vt.setUserId(user.getId());
        vt.setPurpose(VerificationPurpose.EMAIL_CONFIRMATION);
        vt.setTokenHashHex(tokenHashHex);
        vt.setExpiresAt(OffsetDateTime.now().plusMinutes(tokenTtlMinutes));
        vt.setUsedAt(null);
        vt.setUser(user);
        tokenRepo.save(vt);

        RegisterResponse rr = new RegisterResponse();
        rr.setEmail(user.getEmail());
        rr.setName(user.getName());
        rr.setSurname(user.getSurname());
        rr.setId(user.getId().toString());
        rr.setOrganization(user.getOrganization());

        if (creatingCaUser) {
            rr.setMessage("Registration received");
            return new RegistrationResult(true, 202, rr);
        }

        String confirmUrl = publicBaseUrl + "/confirm?token=" + tokenPlain;
        String safeName = user.getName() == null || user.getName().isBlank() ? "there" : user.getName();
        String html = """
                <p>Hi %s,</p>
                <p>Confirm your email by clicking the link below. This link expires in %d minutes and can be used once.</p>
                <p><a href="%s">Confirm my email</a></p>
                <p>If you didn't sign up, please ignore this message.</p>
                """.formatted(escapeHtml(safeName), tokenTtlMinutes, confirmUrl);
        emailSender.send(user.getEmail(), "Confirm your SudoBox account", html);

        rr.setMessage("Registration received. Check your email to confirm.");
        return new RegistrationResult(true, 202, rr);
    }

    /* helpers */
    private static RegisterResponse msg(String m) { var r = new RegisterResponse(); r.setMessage(m); return r; }
    private static String blankToNull(String s) { return (s == null || s.isBlank()) ? null : s.trim(); }
    private static String hexRandom(int nBytes) { byte[] b=new byte[nBytes]; new SecureRandom().nextBytes(b); return HexFormat.of().formatHex(b).toUpperCase(); }
    private static String sha256Hex(String s) {
        try { var md = MessageDigest.getInstance("SHA-256"); return HexFormat.of().formatHex(md.digest(s.getBytes(StandardCharsets.UTF_8))).toUpperCase(); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    private static String escapeHtml(String s) { return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"); }
}
