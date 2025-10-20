package rs.ac.uns.ftn.pki.dbContext;

import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.certificates.repository.CertificateRepository;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;
import rs.ac.uns.ftn.pki.users.repository.VerificationTokenRepository;

@Component
public class UnifiedDbContext implements IUnifiedDbContext {

    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final CertificateRepository certificatesRepository;

    public UnifiedDbContext(
            UserRepository userRepository,
            VerificationTokenRepository verificationTokenRepository,
            CertificateRepository certificatesRepository
    ) {
        this.userRepository = userRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.certificatesRepository = certificatesRepository;
    }

    @Override
    public UserRepository getUserRepository() {
        return userRepository;
    }

    @Override
    public VerificationTokenRepository getVerificationTokenRepository() {
        return verificationTokenRepository;
    }

    @Override
    public CertificateRepository getCertificatesRepository() {
        return certificatesRepository;
    }
}
