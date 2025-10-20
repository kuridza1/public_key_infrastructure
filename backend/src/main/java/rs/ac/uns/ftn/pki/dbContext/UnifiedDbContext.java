package rs.ac.uns.ftn.pki.dbContext;

import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.certRequests.repository.CertificateRequestRepository;
import rs.ac.uns.ftn.pki.certificates.repository.CertificateRepository;
import rs.ac.uns.ftn.pki.crl.repository.RevokedCertificateRepository;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;
import rs.ac.uns.ftn.pki.users.repository.VerificationTokenRepository;

@Component
public class UnifiedDbContext implements IUnifiedDbContext {

    private final UserRepository userRepository;
    private final VerificationTokenRepository verificationTokenRepository;
    private final CertificateRepository certificatesRepository;
    private final RevokedCertificateRepository revokedCertificatesRepository;
    private final CertificateRequestRepository certificateRequestsRepository;

    public UnifiedDbContext(
            UserRepository userRepository,
            VerificationTokenRepository verificationTokenRepository,
            CertificateRepository certificatesRepository,
            RevokedCertificateRepository revokedCertificatesRepository,
            CertificateRequestRepository certificateRequestsRepository
    ) {
        this.userRepository = userRepository;
        this.verificationTokenRepository = verificationTokenRepository;
        this.certificatesRepository = certificatesRepository;
        this.revokedCertificatesRepository = revokedCertificatesRepository;
        this.certificateRequestsRepository = certificateRequestsRepository;
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

    @Override
    public RevokedCertificateRepository getRevokedCertificatesRepository() {
        return revokedCertificatesRepository;
    }

    @Override
    public CertificateRequestRepository getCertificateRequestsRepository() {
        return certificateRequestsRepository;
    }
}
