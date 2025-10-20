package rs.ac.uns.ftn.pki.dbContext;

import rs.ac.uns.ftn.pki.certRequests.CertificateRequestRepository;
import rs.ac.uns.ftn.pki.certificates.repository.CertificateRepository;
import rs.ac.uns.ftn.pki.crl.RevokedCertificateRepository;
import rs.ac.uns.ftn.pki.users.repository.*;

public interface IUnifiedDbContext {

    // User related repositories
    UserRepository getUserRepository();
    VerificationTokenRepository getVerificationTokenRepository();

    // Certificate related repositories
    CertificateRepository getCertificatesRepository();
    RevokedCertificateRepository getRevokedCertificatesRepository();
    CertificateRequestRepository getCertificateRequestsRepository();

    // Key management repositories
    //MasterKeyRepository getMasterKeyRepository();
    //UserKeysRepository getUserKeysRepository();
}
