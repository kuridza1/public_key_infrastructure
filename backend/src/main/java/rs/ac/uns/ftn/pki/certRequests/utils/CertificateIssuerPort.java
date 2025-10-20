package rs.ac.uns.ftn.pki.certRequests.utils;

import java.security.PublicKey;
import java.util.UUID;

import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;

/**
 * Minimal port to issue a certificate from a CSR/public key.
 * Provide an adapter that calls your certificate module (or another system).
 */
@Component
public interface CertificateIssuerPort {
    void issue(IssueCertificateRequest form,
               String caUserId,
               UUID endEntityUserId,
               PublicKey publicKey);
}
