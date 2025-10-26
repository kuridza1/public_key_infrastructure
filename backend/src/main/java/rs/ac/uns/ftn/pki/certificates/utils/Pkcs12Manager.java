package rs.ac.uns.ftn.pki.certificates.utils;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Component
@RequiredArgsConstructor
public class Pkcs12Manager {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Value("${pki.p12.dir}")
    private String dir;

    @Value("${pki.p12.password}")
    private String password;

    /** Save (or update) a key+chain into a per-CA PKCS#12 file with the given alias. */
    public File saveKeyAndChain(String alias, PrivateKey privateKey, X509Certificate[] chain) throws Exception {
        Files.createDirectories(new File(dir).toPath());
        File p12 = new File(dir, alias + ".p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        if (p12.exists()) {
            try (FileInputStream in = new FileInputStream(p12)) {
                ks.load(in, password.toCharArray());
            }
        } else {
            ks.load(null, null);
        }
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
        try (FileOutputStream out = new FileOutputStream(p12)) {
            ks.store(out, password.toCharArray());
        }
        return p12;
    }

    /** Load the private key for a stored certificate (path+alias from DB). */
    public PrivateKey loadPrivateKey(String keystorePath, String alias) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(keystorePath)) {
            ks.load(in, password.toCharArray());
        }
        return (PrivateKey) ks.getKey(alias, password.toCharArray());
    }

    public static X509Certificate parseX509(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
    }
}
