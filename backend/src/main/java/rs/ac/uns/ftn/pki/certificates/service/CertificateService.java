package rs.ac.uns.ftn.pki.certificates.service;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.dtos.CertificateResponse;
import rs.ac.uns.ftn.pki.certificates.dtos.DownloadCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.model.CertificateStatus;
import rs.ac.uns.ftn.pki.dbContext.IUnifiedDbContext;
import rs.ac.uns.ftn.pki.certificates.utils.CertificateBuilder;
import rs.ac.uns.ftn.pki.users.model.Role;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true) // default: keep read ops inside a session (LOB-safe)
public class CertificateService {

    private final IUnifiedDbContext db;

    public CertificateService(IUnifiedDbContext db) {
        this.db = db;
    }

    @Transactional // write
    public void createCertificate(IssueCertificateRequest createCertificateRequest, boolean isAdmin,
                                  String userId, String requestingUserId,
                                  AsymmetricKeyParameter subjectPublicKey,
                                  AsymmetricKeyParameter subjectPrivateKey) {
        if (userId == null || requestingUserId == null)
            throw new RuntimeException("User must be logged in!");

        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("Signing user not found!"));
        var requestingUser = db.getUserRepository().findByIdWithCertificates(UUID.fromString(requestingUserId))
                .orElseThrow(() -> new RuntimeException("Requesting user not found!"));

        if (subjectPublicKey == null) {
            var kpGen = new RSAKeyPairGenerator();
            kpGen.init(new RSAKeyGenerationParameters(
                    BigInteger.valueOf(65537), new SecureRandom(), 2048, 80));
            AsymmetricCipherKeyPair subjectKeyPair = kpGen.generateKeyPair();
            subjectPublicKey = subjectKeyPair.getPublic();
            subjectPrivateKey = subjectKeyPair.getPrivate();
        }

        Certificate signingCertificate;
        if (!"SelfSign".equals(createCertificateRequest.signingCertificate())) {
            var signingSerialNumber = new BigInteger(createCertificateRequest.signingCertificate());

            // FIX: query by serialNumber (NOT findById)
            signingCertificate = db.getCertificatesRepository()
                    .findBySerialNumber(signingSerialNumber)
                    .orElse(null);

            if (signingCertificate == null)
                throw new RuntimeException("Signing certificate not found!");
        } else {
            signingCertificate = null;
        }

        if (!isAdmin && signingCertificate == null)
            throw new RuntimeException("Only admin can issue self signing certificates!");
        if (signingCertificate != null && !signingCertificate.getCanSign())
            throw new RuntimeException("Selected certificate can't be used for signing!");

        CertificateStatus status = signingCertificate != null ? getStatus(signingCertificate) : null;
        if (status != null && status != CertificateStatus.ACTIVE)
            throw new RuntimeException("Selected certificate is " + status.toString().toLowerCase() + "!");

        if (signingCertificate != null && createCertificateRequest.notBefore()
                .isBefore(signingCertificate.getNotBefore().toLocalDateTime()))
            throw new RuntimeException("NotBefore cannot be earlier than the signing certificate's NotBefore!");
        if (signingCertificate != null && createCertificateRequest.notAfter()
                .isAfter(signingCertificate.getNotAfter().toLocalDateTime()))
            throw new RuntimeException("NotAfter cannot be later than the signing certificate's NotAfter!");
        if (createCertificateRequest.notBefore().isAfter(createCertificateRequest.notAfter()))
            throw new RuntimeException("NotBefore cannot be later than the NotAfter!");

        if (!isAdmin && signingCertificate != null &&
                user.getMyCertificates().stream()
                        .noneMatch(c -> c.getSerialNumber().equals(signingCertificate.getSerialNumber())))
            throw new RuntimeException("You don't have control over selected signing certificate!");

        Certificate certificate = CertificateBuilder.createCertificate(
                createCertificateRequest, subjectPublicKey, subjectPrivateKey, signingCertificate, user);

        if (requestingUser.getRole() == Role.EeUser ||
                (requestingUser.getRole() == Role.CaUser && certificate.getCanSign())) {
            requestingUser.getMyCertificates().add(certificate);
        }

        db.getCertificatesRepository().save(certificate);
        db.getUserRepository().save(requestingUser);
    }

    public List<CertificateResponse> getAllCertificates() {
        var all = db.getCertificatesRepository().findAll();
        return all.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    public List<CertificateResponse> getAllValidSigningCertificates() {
        var allSigning = db.getCertificatesRepository().findByCanSignTrue();
        var valid = allSigning.stream()
                .filter(c -> getStatus(c) == CertificateStatus.ACTIVE)
                .collect(Collectors.toList());
        return valid.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    public List<CertificateResponse> getValidSigningCertificatesCaUserDoesntHave(String caUserId) {
        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(caUserId))
                .orElseThrow(() -> new RuntimeException("User not found!"));

        var allSigning = db.getCertificatesRepository().findByCanSignWithSigningCertificate();
        var notOwned = allSigning.stream()
                .filter(c -> !user.getMyCertificates().contains(c))
                .collect(Collectors.toList());

        var valid = notOwned.stream()
                .filter(c -> getStatus(c) == CertificateStatus.ACTIVE)
                .collect(Collectors.toList());

        return valid.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    public List<CertificateResponse> getMyCertificates(String userId) {
        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found!"));
        return user.getMyCertificates().stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    public List<CertificateResponse> getMyValidCertificates(String userId) {
        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found!"));
        var valid = user.getMyCertificates().stream()
                .filter(c -> getStatus(c) == CertificateStatus.ACTIVE)
                .collect(Collectors.toList());
        return valid.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    public List<CertificateResponse> getCertificatesSignedByMe(String userId) {
        var list = db.getCertificatesRepository().findBySignedById(UUID.fromString(userId));
        return list.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    @Transactional // write
    public void addCertificateToCaUser(rs.ac.uns.ftn.pki.certificates.dtos.AddCertificateToCaUserRequest req) {
        var user = db.getUserRepository()
                .findByIdWithCertificates(UUID.fromString(req.caUserId()))
                .orElseThrow(() -> new RuntimeException("User not found!"));

        // FIX: query by serialNumber (NOT findById)
        var certificate = db.getCertificatesRepository()
                .findBySerialNumber(new BigInteger(req.newCertificateSerialNumber()))
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        user.getMyCertificates().add(certificate);
        db.getUserRepository().save(user);
    }

    @Transactional(readOnly = true)
    public byte[] getCertificateWithPasswordAsPkcs12(DownloadCertificateRequest request,
                                                     UUID requesterId, Role requesterRole) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        BigInteger serialNumber = new BigInteger(request.getCertificateSerialNumber());

        Certificate eeCertificate = getCertificate(serialNumber)
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        var user = db.getUserRepository().findByIdWithCertificates(requesterId)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        boolean requesterContainsCert = user.getMyCertificates().contains(eeCertificate);
        boolean certSignedByRequester = eeCertificate.getSignedBy().getId().equals(requesterId);

        if (!requesterContainsCert && !certSignedByRequester && requesterRole != Role.Admin) {
            throw new RuntimeException("You cannot download certificates that aren't yours!");
        }

        // Build certificate chain
        Certificate current = eeCertificate;
        while (current != null) {
            if (current.getEncodedValue() == null || current.getEncodedValue().trim().isEmpty())
                throw new RuntimeException("Certificate " + current.getSerialNumber() + " has no encoded value!");

            byte[] bytes = Base64.getDecoder().decode(current.getEncodedValue());
            X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
            chain.add(x509);

            if (current.getSigningCertificate() != null)
                current = getCertificate(current.getSigningCertificate().getSerialNumber()).orElse(null);
            else
                current = null;
        }

        if (chain.isEmpty())
            throw new RuntimeException("No certificates in chain!");

        // Convert BC key to java.security.PrivateKey if present
        java.security.PrivateKey javaPrivateKey = null;
        AsymmetricKeyParameter bcPrivateKey = eeCertificate.getPrivateKey();
        if (bcPrivateKey != null && bcPrivateKey.isPrivate()) {
            PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(bcPrivateKey);
            javaPrivateKey = new JcaPEMKeyConverter().getPrivateKey(pkInfo);
        }

        // Create PKCS12 keystore
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        pkcs12.load(null, null);
        String alias = chain.get(0).getSubjectDN().toString();

        if (javaPrivateKey != null) {
            X509Certificate[] certChain = chain.toArray(new X509Certificate[0]);
            pkcs12.setKeyEntry(alias, javaPrivateKey, request.getPassword().toCharArray(), certChain);
        } else {
            pkcs12.setCertificateEntry(alias, chain.get(0));
            for (int i = 1; i < chain.size(); i++) {
                pkcs12.setCertificateEntry(alias + "-chain-" + i, chain.get(i));
            }
        }

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            pkcs12.store(baos, request.getPassword().toCharArray());
            return baos.toByteArray();
        }
    }

    // FIX: use the new repository method that fetch-joins by serialNumber
    private Optional<Certificate> getCertificate(BigInteger serialNumber) {
        return db.getCertificatesRepository()
                .findBySerialNumberWithSigningCertificateAndSignedBy(serialNumber);
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

        var now = LocalDateTime.now();
        var notAfter = certificate.getNotAfter();
        var notBefore = certificate.getNotBefore();

        if (now.isAfter(notAfter.toLocalDateTime())) {
            var parentStatus = certificate.getSigningCertificate() == null ?
                    CertificateStatus.EXPIRED : getStatus(certificate.getSigningCertificate(),
                    original != null ? original : certificate, depth + 1);
            return parentStatus == CertificateStatus.ACTIVE ? CertificateStatus.EXPIRED : parentStatus;
        }
        if (now.isBefore(notBefore.toLocalDateTime())) {
            var parentStatus = certificate.getSigningCertificate() == null ?
                    CertificateStatus.DORMANT : getStatus(certificate.getSigningCertificate(),
                    original != null ? original : certificate, depth + 1);
            return parentStatus == CertificateStatus.ACTIVE ? CertificateStatus.DORMANT : parentStatus;
        }
        if (certificate.getSigningCertificate() == null)
            return CertificateStatus.ACTIVE;
        return getStatus(certificate.getSigningCertificate(), original != null ? original : certificate, depth + 1);
    }

    private boolean isCertificateSignedBy(String certB64, String issuerB64) {
        if (certB64 == null || certB64.isEmpty() || issuerB64 == null || issuerB64.isEmpty())
            return false;
        try {
            var certFactory = java.security.cert.CertificateFactory.getInstance("X.509");
            var cert = (X509Certificate) certFactory.generateCertificate(
                    new java.io.ByteArrayInputStream(Base64.getDecoder().decode(certB64)));
            var issuer = (X509Certificate) certFactory.generateCertificate(
                    new java.io.ByteArrayInputStream(Base64.getDecoder().decode(issuerB64)));
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isRevoked(Certificate certificate) {
        return db.getRevokedCertificatesRepository()
                .existsRevokedCertificateByCertificateSerialNumber((certificate.getSerialNumber()));
    }
}
