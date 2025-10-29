package rs.ac.uns.ftn.pki.certificates.service;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.dtos.AddCertificateToCaUserRequest;
import rs.ac.uns.ftn.pki.certificates.dtos.CertificateResponse;
import rs.ac.uns.ftn.pki.certificates.dtos.DownloadCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.model.CertificateStatus;
import rs.ac.uns.ftn.pki.certificates.utils.CertificateBuilder;
import rs.ac.uns.ftn.pki.certificates.utils.Pkcs12Manager;
import rs.ac.uns.ftn.pki.dbContext.IUnifiedDbContext;
import rs.ac.uns.ftn.pki.users.model.Role;
import rs.ac.uns.ftn.pki.users.model.User;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
public class CertificateService {

    private final IUnifiedDbContext db;
    private final CertificateBuilder builder;   // builder bean
    private final Pkcs12Manager pkcs12Manager;  // keystore manager
    private final PrivateKeyVault privateKeyVault;

    public CertificateService(IUnifiedDbContext db,
                              CertificateBuilder builder,
                              Pkcs12Manager pkcs12Manager, PrivateKeyVault privateKeyVault) {
        this.db = db;
        this.builder = builder;
        this.pkcs12Manager = pkcs12Manager;
        this.privateKeyVault = privateKeyVault;
    }

    // ===================== ISSUE CERTIFICATE =====================

    @Transactional
    public void createCertificate(IssueCertificateRequest req, boolean isAdmin,
                                  String userId, String requestingUserId,
                                  AsymmetricKeyParameter subjectPublicKey,
                                  AsymmetricKeyParameter subjectPrivateKey) {

        if (userId == null || requestingUserId == null)
            throw new RuntimeException("User must be logged in!");

        UUID issuerUserId = UUID.fromString(userId);
        UUID requesterUserId = UUID.fromString(requestingUserId);

        User user = db.getUserRepository().findByIdWithCertificates(issuerUserId)
                .orElseThrow(() -> new RuntimeException("Signing user not found!"));
        User requestingUser = db.getUserRepository().findByIdWithCertificates(requesterUserId)
                .orElseThrow(() -> new RuntimeException("Requesting user not found!"));

        // Generate subject RSA pair if not provided
        if (subjectPublicKey == null || subjectPrivateKey == null) {
            RSAKeyPairGenerator kpGen = new RSAKeyPairGenerator();
            kpGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            subjectPublicKey = kp.getPublic();
            subjectPrivateKey = kp.getPrivate();
        }

        // Resolve issuer (or self-sign)
        Certificate issuer;
        if (!"SelfSign".equals(req.signingCertificate())) {
            BigInteger serial = new BigInteger(req.signingCertificate());
            issuer = db.getCertificatesRepository().findBySerialNumber(serial)
                    .orElseThrow(() -> new RuntimeException("Signing certificate not found!"));
        } else {
            issuer = null;
        }

        // Authorization & validity guards
        if (!isAdmin && issuer == null)
            throw new RuntimeException("Only admin can issue self signing certificates!");
        if (issuer != null && !issuer.getCanSign())
            throw new RuntimeException("Selected certificate can't be used for signing!");

        CertificateStatus status = issuer != null ? getStatus(issuer) : null;
        if (status != null && status != CertificateStatus.ACTIVE)
            throw new RuntimeException("Selected certificate is " + status.toString().toLowerCase() + "!");

        if (issuer != null && req.notBefore().isBefore(issuer.getNotBefore().toLocalDateTime()))
            throw new RuntimeException("NotBefore cannot be earlier than the signing certificate's NotBefore!");
        if (issuer != null && req.notAfter().isAfter(issuer.getNotAfter().toLocalDateTime()))
            throw new RuntimeException("NotAfter cannot be later than the signing certificate's NotAfter!");
        if (req.notBefore().isAfter(req.notAfter()))
            throw new RuntimeException("NotBefore cannot be later than the NotAfter!");

        // ✅ Ownership check (FIXED): ensure the CA actually OWNS the issuing cert
        if (!isAdmin && issuer != null) {
            OffsetDateTime now = OffsetDateTime.now();
            boolean ownsIssuer = db.getCertificatesRepository()
                    .findActiveSigningAssignedToUser(issuerUserId, now)
                    .stream()
                    .anyMatch(c -> c.getSerialNumber().equals(issuer.getSerialNumber()));
            if (!ownsIssuer) {
                throw new RuntimeException("You don't have control over selected signing certificate!");
            }
        }

        // Issue certificate
        Certificate certificate = builder.createCertificate(
                req, subjectPublicKey, subjectPrivateKey, issuer, user);

        // private key encription
        UUID orgId = user.getId();
        privateKeyVault.storeForCertificate(orgId, certificate.getSerialNumber(), subjectPrivateKey);
        certificate.setPrivateKey(null);

        if (requestingUser.getRole() == Role.EeUser ||
                (requestingUser.getRole() == Role.CaUser && certificate.getCanSign())) {
            requestingUser.getAssignedCertificates().add(certificate);
        }

        db.getCertificatesRepository().save(certificate);
        db.getUserRepository().save(requestingUser);
    }

    // ===================== QUERIES =====================

    public List<CertificateResponse> getAllCertificates() {
        return db.getCertificatesRepository().findAll().stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    // (kept for compatibility) – system-wide valid signing certs
    public List<CertificateResponse> getAllValidSigningCertificates() {
        return db.getCertificatesRepository().findByCanSignTrue().stream()
                .filter(c -> getStatus(c) == CertificateStatus.ACTIVE)
                .map(c -> CertificateResponse.createDto(c, CertificateStatus.ACTIVE.toString()))
                .collect(Collectors.toList());
    }

    // Fast version using DB-side filtering
    public List<CertificateResponse> getAllValidSigningCertificatesFast() {
        var now = OffsetDateTime.now();
        return db.getCertificatesRepository().findAllActiveSigning(now).stream()
                .map(c -> CertificateResponse.createDto(c, CertificateStatus.ACTIVE.toString()))
                .toList();
    }

    // CA: list of valid signing certs that the CA user does NOT have (DB-only, no in-memory user certs)
    public List<CertificateResponse> getValidSigningCertificatesCaUserDoesntHave(String caUserId) {
        var userId = UUID.fromString(caUserId);
        db.getUserRepository().findByIdAndRole(userId, rs.ac.uns.ftn.pki.users.model.Role.CaUser)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        var now = OffsetDateTime.now();
        return db.getCertificatesRepository()
                .findActiveSigningNotAssignedTo(userId, now).stream()
                .map(c -> CertificateResponse.createDto(c, CertificateStatus.ACTIVE.toString()))
                .toList();
    }

    // ✅ "My certificates" = certificates where signedBy == user (no inversion)
    public List<CertificateResponse> getMyCertificates(String userId) {
        UUID uid = UUID.fromString(userId);

        var user = db.getUserRepository().findById(uid)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        // “My” means: what’s assigned to me (for both CA and EE)
        var certs = db.getCertificatesRepository().findAssignedToUser(uid);

        return certs.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .toList();
    }

    // ✅ "My valid certificates" (all types) = my certs filtered to ACTIVE
    public List<CertificateResponse> getMyValidCertificates(String userId) {
        UUID uid = UUID.fromString(userId);
        db.getUserRepository().findById(uid).orElseThrow(() -> new RuntimeException("User not found!"));

        return db.getCertificatesRepository().findAssignedToUser(uid).stream()
                .filter(c -> getStatus(c) == CertificateStatus.ACTIVE)
                .map(c -> CertificateResponse.createDto(c, CertificateStatus.ACTIVE.toString()))
                .toList();
    }

    // ✅ "My valid signing certificates" only (DB-side filtered, time-valid & not revoked)
    public List<CertificateResponse> getMyValidSigningCertificates(String userId) {
        var now = OffsetDateTime.now();
        return db.getCertificatesRepository()
                .findActiveSigningByIssuer(UUID.fromString(userId), now).stream()
                .map(c -> CertificateResponse.createDto(c, CertificateStatus.ACTIVE.toString()))
                .toList();
    }

    public List<CertificateResponse> getCertificatesSignedByMe(String userId) {
        return db.getCertificatesRepository().findBySignedById(UUID.fromString(userId)).stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    @Transactional
    public void addCertificateToCaUser(AddCertificateToCaUserRequest req) {
        var user = db.getUserRepository()
                .findByIdWithCertificates(UUID.fromString(req.caUserId()))
                .orElseThrow(() -> new RuntimeException("User not found!"));

        var certificate = db.getCertificatesRepository()
                .findBySerialNumber(new BigInteger(req.newCertificateSerialNumber()))
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        // Set owner side
        certificate.setSignedBy(user);
        // Keep both sides in sync in memory (optional)
        user.getAssignedCertificates().add(certificate);
        db.getCertificatesRepository().save(certificate);
    }

    // ===================== DOWNLOAD (PKCS#12 EXPORT) =====================

    // src/main/java/.../certificates/service/CertificateService.java

    @Transactional(readOnly = true)
    public byte[] getCertificateWithPasswordAsPkcs12(DownloadCertificateRequest request,
                                                     UUID requesterId, Role requesterRole) throws Exception {
        BigInteger serial = new BigInteger(request.getCertificateSerialNumber());
        Certificate eeCert = getCertificate(serial)
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        var user = db.getUserRepository().findByIdWithCertificates(requesterId)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        boolean requesterOwns = user.getAssignedCertificates().contains(eeCert);
        boolean signedByRequester = eeCert.getSignedBy() != null && eeCert.getSignedBy().getId().equals(requesterId);

        if (!requesterOwns && !signedByRequester && requesterRole != Role.Admin) {
            throw new RuntimeException("You cannot download certificates that aren't yours!");
        }

        // Build trust chain (unchanged)
        List<X509Certificate> chain = buildChain(eeCert);
        if (chain.isEmpty()) throw new RuntimeException("No certificates in chain!");

        // === NEW: try DB vault first ===
        java.security.PrivateKey privateKey = null;
        try {
            UUID orgId = user.getId(); // same helper as above
            privateKey = privateKeyVault.loadForCertificate(orgId, eeCert.getSerialNumber());
        } catch (Exception ignored) {
            // ignore, we’ll fallback to filesystem if needed
        }

        // === Fallback to old PKCS#12 on disk ===
        if (privateKey == null && eeCert.getKeystorePath() != null && eeCert.getKeystoreAlias() != null) {
            try {
                privateKey = pkcs12Manager.loadPrivateKey(eeCert.getKeystorePath(), eeCert.getKeystoreAlias());
            } catch (Exception ignored) { /* cert-only export below */ }
        }

        // Build the P12 to return
        KeyStore p12 = KeyStore.getInstance("PKCS12");
        p12.load(null, null);
        String alias = chain.get(0).getSubjectX500Principal().getName();

        if (privateKey != null) {
            p12.setKeyEntry(alias, privateKey, request.getPassword().toCharArray(),
                    chain.toArray(new X509Certificate[0]));
        } else {
            // cert-only export (typical for CSR EE certs)
            p12.setCertificateEntry(alias, chain.get(0));
            for (int i = 1; i < chain.size(); i++) {
                p12.setCertificateEntry(alias + "-chain-" + i, chain.get(i));
            }
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            p12.store(baos, request.getPassword().toCharArray());
            return baos.toByteArray();
        }
    }


    // ===================== HELPERS =====================

    private Optional<Certificate> getCertificate(BigInteger serialNumber) {
        return db.getCertificatesRepository()
                .findBySerialNumberWithSigningCertificateAndSignedBy(serialNumber);
    }

    /** Build X509 chain (end-entity -> ... -> root) by following signingCertificate refs. */
    private List<X509Certificate> buildChain(Certificate leaf) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate cur = leaf;

        while (cur != null) {
            String enc = cur.getEncodedValue();
            if (enc == null || enc.isBlank()) {
                throw new RuntimeException("Certificate " + cur.getSerialNumber() + " has no encoded value!");
            }
            byte[] der = Base64.getDecoder().decode(enc);
            X509Certificate x509 = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            out.add(x509);

            if (cur.getSigningCertificate() == null) break;
            cur = getCertificate(cur.getSigningCertificate().getSerialNumber()).orElse(null);
        }
        return out;
    }

    public CertificateStatus getStatus(Certificate certificate) {
        return getStatus(certificate, null, 0);
    }

    private CertificateStatus getStatus(Certificate certificate, Certificate original, int depth) {
        if (certificate.getSigningCertificate() != null &&
                !isCertificateSignedBy(certificate.getEncodedValue(), certificate.getSigningCertificate().getEncodedValue()))
            return CertificateStatus.INVALID;

        if (certificate.getSigningCertificate() != null && depth > certificate.getSigningCertificate().getPathLen())
            return CertificateStatus.PROHIBITED;

        if (certificate.getSerialNumber().equals(original != null ? original.getSerialNumber() : null))
            return CertificateStatus.CIRCULAR;

        if (isRevoked(certificate))
            return CertificateStatus.REVOKED;

        LocalDateTime now = LocalDateTime.now();
        var notAfter = certificate.getNotAfter();
        var notBefore = certificate.getNotBefore();

        if (now.isAfter(notAfter.toLocalDateTime())) {
            var parentStatus = certificate.getSigningCertificate() == null
                    ? CertificateStatus.EXPIRED
                    : getStatus(certificate.getSigningCertificate(),
                    original != null ? original : certificate, depth + 1);
            return parentStatus == CertificateStatus.ACTIVE ? CertificateStatus.EXPIRED : parentStatus;
        }

        if (now.isBefore(notBefore.toLocalDateTime())) {
            var parentStatus = certificate.getSigningCertificate() == null
                    ? CertificateStatus.DORMANT
                    : getStatus(certificate.getSigningCertificate(),
                    original != null ? original : certificate, depth + 1);
            return parentStatus == CertificateStatus.ACTIVE ? CertificateStatus.DORMANT : parentStatus;
        }

        if (certificate.getSigningCertificate() == null)
            return CertificateStatus.ACTIVE;

        return getStatus(certificate.getSigningCertificate(), original != null ? original : certificate, depth + 1);
    }

    private boolean isCertificateSignedBy(String certB64, String issuerB64) {
        if (certB64 == null || certB64.isEmpty() || issuerB64 == null || issuerB64.isEmpty()) return false;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(certB64)));
            X509Certificate issuer = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(Base64.getDecoder().decode(issuerB64)));
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isRevoked(Certificate certificate) {
        return db.getRevokedCertificatesRepository()
                .existsRevokedCertificateByCertificateSerialNumber(certificate.getSerialNumber());
    }
}
