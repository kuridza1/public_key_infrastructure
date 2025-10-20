package rs.ac.uns.ftn.pki.certRequests.utils;

import java.security.PublicKey;
import java.util.UUID;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;

@FunctionalInterface
public interface CertificateIssuerPort {
    void issue(IssueCertificateRequest form,
               String caUserId,
               UUID endEntityUserId,
               AsymmetricKeyParameter publicKey);
}


