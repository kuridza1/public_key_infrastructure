package rs.ac.uns.ftn.pki.crl.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@Configuration
public class CrlSigningConfig {

    @Value("${security.crl.keystore.path}")
    private Resource keystoreResource;

    @Value("${security.crl.keystore.password}")
    private String password;

    @Value("${security.crl.keystore.alias:}")
    private String alias; // optional

    @Bean
    public KeyStore crlKeyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = keystoreResource.getInputStream()) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }

    @Bean
    public PrivateKey crlSigningPrivateKey(KeyStore crlKeyStore) throws Exception {
        String useAlias = resolveAlias(crlKeyStore, alias);
        return (PrivateKey) crlKeyStore.getKey(useAlias, password.toCharArray());
    }

    @Bean
    public X509Certificate crlIssuerCertificate(KeyStore crlKeyStore) throws Exception {
        String useAlias = resolveAlias(crlKeyStore, alias);
        return (X509Certificate) crlKeyStore.getCertificate(useAlias);
    }

    private static String resolveAlias(KeyStore ks, String preferredAlias) throws Exception {
        if (preferredAlias != null && !preferredAlias.isBlank()) {
            return preferredAlias;
        }
        Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) return a; // pick first private key entry
        }
        throw new IllegalStateException("No PrivateKey entry found in PKCS#12 keystore.");
    }
}
