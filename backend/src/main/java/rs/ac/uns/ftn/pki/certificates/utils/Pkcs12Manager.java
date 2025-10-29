package rs.ac.uns.ftn.pki.certificates.utils;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

// rs.ac.uns.ftn.pki.certificates.utils.Pkcs12Manager

// rs.ac.uns.ftn.pki.certificates.utils.Pkcs12Manager
@Component
public class Pkcs12Manager {

    private final Path baseDir;
    private final char[] defaultPassword;

    public Pkcs12Manager(
            @Value("${pki.p12.dir}") String baseDirProp,
            @Value("${pki.p12.password}") String defaultPasswordProp
    ) {
        this.baseDir = Path.of(baseDirProp).toAbsolutePath().normalize();
        this.defaultPassword = defaultPasswordProp.toCharArray();
    }

    /** Saves a private key + chain into a PKCS#12 under baseDir, returns the File. */
    public File saveKeyAndChain(String alias, PrivateKey key, java.security.cert.X509Certificate[] chain) {
        try {
            // Decide folder: self-signed (root) -> root/keys, else intermediate/keys
            boolean isRoot = isSelfSigned(chain[0]);
            Path targetDir = baseDir
                    .resolve(isRoot ? Path.of("root", "keys") : Path.of("intermediate", "keys"))
                    .normalize();

            Files.createDirectories(targetDir);

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry(aliasSan(alias), key, defaultPassword, chain);

            Path p12Path = targetDir.resolve(aliasSan(alias) + ".p12");
            try (var fos = Files.newOutputStream(p12Path)) {
                ks.store(fos, defaultPassword);
            }
            return p12Path.toFile();
        } catch (Exception e) {
            throw new RuntimeException("Failed to store PKCS#12", e);
        }
    }

    public PrivateKey loadPrivateKey(String keystorePath, String alias) throws Exception {
        try (var in = Files.newInputStream(Path.of(keystorePath))) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(in, defaultPassword);
            return (PrivateKey) ks.getKey(alias, defaultPassword);
        }
    }

    public static java.security.cert.X509Certificate parseX509(byte[] der) throws Exception {
        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der));
    }

    // --- helpers ---
    private static boolean isSelfSigned(java.security.cert.X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey()); // cryptographic self-signature check
            return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
        } catch (Exception e) {
            return false;
        }
    }

    private static String aliasSan(String alias) {
        return alias.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}


