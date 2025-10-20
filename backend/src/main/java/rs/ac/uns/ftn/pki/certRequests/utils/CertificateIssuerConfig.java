package rs.ac.uns.ftn.pki.certRequests.utils;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;

@Configuration
public class CertificateIssuerConfig {

    @Bean
    CertificateIssuerPort certificateIssuerPort(CertificateService certificateService) {
        return (form, caUserId, endEntityUserId, publicKey) ->
                certificateService.createCertificate(
                        form, false, caUserId, endEntityUserId.toString(), publicKey, null
                );
    }
}
