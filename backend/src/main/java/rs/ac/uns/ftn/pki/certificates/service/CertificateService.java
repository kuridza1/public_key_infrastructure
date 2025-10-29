package rs.ac.uns.ftn.pki.certificates.service;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.dtos.CertificateResponse;
import rs.ac.uns.ftn.pki.certificates.dtos.DownloadCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.model.CertificateStatus;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.BasicConstraintsValue;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.ExtendedKeyUsageValue;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.KeyUsageValue;
import rs.ac.uns.ftn.pki.dbContext.IUnifiedDbContext;
import rs.ac.uns.ftn.pki.certificates.utils.CertificateBuilder;
import rs.ac.uns.ftn.pki.template.CertificateTemplate;
import rs.ac.uns.ftn.pki.template.CertificateTemplateService;
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
@Transactional(readOnly = true)
public class CertificateService {

    private final IUnifiedDbContext db;

    @Lazy
    @Autowired
    private CertificateTemplateService templateService;

    // Remove templateService from constructor
    public CertificateService(IUnifiedDbContext db) {
        this.db = db;
    }

    // Your existing createCertificate method remains the same
    @Transactional
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

        if (!isAdmin && user.getMyCertificates().stream()
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

    public List<CertificateResponse> getValidSigningCertificatesCaUserDoesntHave(String caUserId) {
        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(caUserId))
                .orElseThrow(() -> new RuntimeException("User not found!"));

        // Use the repository method you actually have
        var allSigning = db.getCertificatesRepository().findByCanSignTrue();

        // Get serial numbers of certificates the user already owns
        Set<BigInteger> userCertificateSerials = user.getMyCertificates().stream()
                .map(Certificate::getSerialNumber)
                .collect(Collectors.toSet());

        // Filter: valid certificates that user doesn't own
        List<Certificate> validNotOwned = allSigning.stream()
                .filter(cert -> {
                    CertificateStatus status = getStatus(cert);
                    return status == CertificateStatus.ACTIVE;
                })
                .filter(cert -> !userCertificateSerials.contains(cert.getSerialNumber()))
                .collect(Collectors.toList());

        return validNotOwned.stream()
                .map(cert -> CertificateResponse.createDto(cert, getStatus(cert).toString()))
                .collect(Collectors.toList());
    }

    @Transactional
    public void createCertificateWithTemplate(IssueCertificateRequest request,
                                              String userId,
                                              String requestingUserId,
                                              AsymmetricKeyParameter subjectPublicKey,
                                              AsymmetricKeyParameter subjectPrivateKey) {

        // Validate and apply template if specified
        IssueCertificateRequest processedRequest = request;
        if (request.templateId() != null) {
            processedRequest = validateAndApplyTemplate(request, userId);
        }

        // Continue with your existing certificate creation logic
        createCertificate(processedRequest, isAdmin(userId), userId, requestingUserId, subjectPublicKey, subjectPrivateKey);
    }

    private IssueCertificateRequest validateAndApplyTemplate(IssueCertificateRequest request, String userId) {
        var user = db.getUserRepository().findByIdWithCertificates(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("Signing user not found!"));

        var template = templateService.getTemplatesForCaCertificate(request.templateId(), user).stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Template not found or access denied"));

        // Validate template usage permissions
        templateService.validateTemplateUsage(template, user);

        // Validate Common Name against template regex
        if (template.getCommonNameRegex() != null && !template.getCommonNameRegex().isEmpty()) {
            if (!request.commonName().matches(template.getCommonNameRegex())) {
                throw new RuntimeException(
                        String.format("Common Name '%s' does not match template pattern '%s'",
                                request.commonName(), template.getCommonNameRegex())
                );
            }
        }

        // Validate SAN against template regex
        if (template.getSanRegex() != null && !template.getSanRegex().isEmpty() &&
                request.subjectAlternativeNames() != null) {
            String sanString = extractSanString(request.subjectAlternativeNames());
            if (!sanString.matches(template.getSanRegex())) {
                throw new RuntimeException(
                        String.format("Subject Alternative Names do not match template pattern '%s'",
                                template.getSanRegex())
                );
            }
        }

        // Validate TTL against template maximum
        if (template.getMaxTtlDays() != null) {
            long requestedDays = java.time.Duration.between(
                    request.notBefore(), request.notAfter()).toDays();
            if (requestedDays > template.getMaxTtlDays()) {
                throw new RuntimeException(
                        String.format("Validity (%d days) exceeds template maximum (%d days)",
                                requestedDays, template.getMaxTtlDays())
                );
            }
        }

        // Apply template extensions
        return applyTemplateExtensions(request, template);
    }

    private String extractSanString(Object subjectAlternativeNames) {
        // Implement based on your ListOfNames implementation
        if (subjectAlternativeNames == null) return "";
        return subjectAlternativeNames.toString(); // Adjust as needed
    }

    private IssueCertificateRequest applyTemplateExtensions(IssueCertificateRequest request, CertificateTemplate template) {
        IssueCertificateRequest result = request;

        // Apply Key Usage from template if not explicitly provided
        if ((request.keyUsage() == null || request.keyUsage().isEmpty()) &&
                template.getKeyUsage() != null) {
            result = applyKeyUsageFromTemplate(result, template);
        }

        // Apply Extended Key Usage from template if not explicitly provided
        if ((request.extendedKeyUsage() == null || request.extendedKeyUsage().isEmpty()) &&
                template.getExtendedKeyUsage() != null) {
            result = applyExtendedKeyUsageFromTemplate(result, template);
        }

        // Apply Basic Constraints from template if not explicitly provided
        if (request.basicConstraints() == null && template.getBasicConstraints() != null) {
            result = applyBasicConstraintsFromTemplate(result, template);
        }

        return result;
    }

    private IssueCertificateRequest applyKeyUsageFromTemplate(IssueCertificateRequest request, CertificateTemplate template) {
        Collection<KeyUsageValue> keyUsage = parseKeyUsage(template.getKeyUsage());
        return new IssueCertificateRequest(
                request.signingCertificate(),
                request.commonName(),
                request.organization(),
                request.organizationalUnit(),
                request.email(),
                request.country(),
                request.notBefore(),
                request.notAfter(),
                keyUsage, // Applied from template
                request.extendedKeyUsage(),
                request.subjectAlternativeNames(),
                request.issuerAlternativeNames(),
                request.nameConstraints(),
                request.basicConstraints(),
                request.certificatePolicy(),
                request.templateId(),
                request.customExtensions()
        );
    }

    private IssueCertificateRequest applyExtendedKeyUsageFromTemplate(IssueCertificateRequest request, CertificateTemplate template) {
        Collection<ExtendedKeyUsageValue> extendedKeyUsage = parseExtendedKeyUsage(template.getExtendedKeyUsage());
        return new IssueCertificateRequest(
                request.signingCertificate(),
                request.commonName(),
                request.organization(),
                request.organizationalUnit(),
                request.email(),
                request.country(),
                request.notBefore(),
                request.notAfter(),
                request.keyUsage(),
                extendedKeyUsage, // Applied from template
                request.subjectAlternativeNames(),
                request.issuerAlternativeNames(),
                request.nameConstraints(),
                request.basicConstraints(),
                request.certificatePolicy(),
                request.templateId(),
                request.customExtensions()
        );
    }

    private IssueCertificateRequest applyBasicConstraintsFromTemplate(IssueCertificateRequest request, CertificateTemplate template) {
        BasicConstraintsValue basicConstraints = parseBasicConstraints(template.getBasicConstraints());
        return new IssueCertificateRequest(
                request.signingCertificate(),
                request.commonName(),
                request.organization(),
                request.organizationalUnit(),
                request.email(),
                request.country(),
                request.notBefore(),
                request.notAfter(),
                request.keyUsage(),
                request.extendedKeyUsage(),
                request.subjectAlternativeNames(),
                request.issuerAlternativeNames(),
                request.nameConstraints(),
                basicConstraints, // Applied from template
                request.certificatePolicy(),
                request.templateId(),
                request.customExtensions()
        );
    }

    // Parsing methods - implement based on your actual enum/class structure
    private Collection<KeyUsageValue> parseKeyUsage(String keyUsageString) {
        if (keyUsageString == null || keyUsageString.trim().isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.stream(keyUsageString.split("\\s*,\\s*"))
                .map(String::trim)
                .map(this::parseKeyUsageValue)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private KeyUsageValue parseKeyUsageValue(String value) {
        try {
            return KeyUsageValue.valueOf(value);
        } catch (IllegalArgumentException e) {
            // Handle unknown key usage values
            return null;
        }
    }

    private Collection<ExtendedKeyUsageValue> parseExtendedKeyUsage(String extendedKeyUsageString) {
        if (extendedKeyUsageString == null || extendedKeyUsageString.trim().isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.stream(extendedKeyUsageString.split("\\s*,\\s*"))
                .map(String::trim)
                .map(this::parseExtendedKeyUsageValue)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private ExtendedKeyUsageValue parseExtendedKeyUsageValue(String value) {
        try {
            return ExtendedKeyUsageValue.valueOf(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private BasicConstraintsValue parseBasicConstraints(String basicConstraintsString) {
        if (basicConstraintsString == null || basicConstraintsString.trim().isEmpty()) {
            return null;
        }

        // Parse format: "CA:true,pathlen:0" or similar
        boolean ca = basicConstraintsString.toLowerCase().contains("ca:true");
        Integer pathLen = extractPathLen(basicConstraintsString);

        // Adjust based on your BasicConstraintsValue constructor
        return new BasicConstraintsValue(ca, pathLen != null ? pathLen : -1);
    }

    private Integer extractPathLen(String constraints) {
        // Simple implementation - adjust as needed
        if (constraints.contains("pathlen:")) {
            try {
                String pathLenPart = constraints.split("pathlen:")[1].split("[,\\s]")[0];
                return Integer.parseInt(pathLenPart.trim());
            } catch (Exception e) {
                // Log error
            }
        }
        return null;
    }

    private boolean isAdmin(String userId) {
        var user = db.getUserRepository().findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getRole().name().equals("Admin");
    }

    // Remove the duplicate method - keep only one createCertificateWithTemplate
    // @Transactional
    // public void createCertificateWithTemplate(IssueCertificateRequest request, UUID templateId, ...)
    // ^^ This duplicate method should be removed
    @Transactional(readOnly = true)
    public byte[] getCertificateWithPasswordAsPkcs12(DownloadCertificateRequest request,
                                                     UUID requesterId, Role requesterRole) throws Exception {
        List<X509Certificate> chain = new ArrayList<>();
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        BigInteger serialNumber = new BigInteger(request.getCertificateSerialNumber());

        // Get the end-entity certificate
        Certificate eeCertificate = getCertificate(serialNumber)
                .orElseThrow(() -> new RuntimeException("Certificate not found!"));

        var user = db.getUserRepository().findByIdWithCertificates(requesterId)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        // Authorization check
        boolean requesterContainsCert = user.getMyCertificates().contains(eeCertificate);
        boolean certSignedByRequester = eeCertificate.getSignedBy() != null &&
                eeCertificate.getSignedBy().getId().equals(requesterId);

        if (!requesterContainsCert && !certSignedByRequester && requesterRole != Role.Admin) {
            throw new RuntimeException("You cannot download certificates that aren't yours!");
        }

        // Build certificate chain
        Certificate current = eeCertificate;
        while (current != null) {
            if (current.getEncodedValue() == null || current.getEncodedValue().trim().isEmpty()) {
                throw new RuntimeException("Certificate " + current.getSerialNumber() + " has no encoded value!");
            }

            // Decode Base64 and create X509Certificate
            byte[] bytes = Base64.getDecoder().decode(current.getEncodedValue());
            X509Certificate x509 = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(bytes));
            chain.add(x509);

            // Move to the signing certificate (parent)
            if (current.getSigningCertificate() != null) {
                current = getCertificate(current.getSigningCertificate().getSerialNumber()).orElse(null);
            } else {
                current = null; // Root certificate reached
            }
        }

        if (chain.isEmpty()) {
            throw new RuntimeException("No certificates in chain!");
        }

        // Reverse the chain to have EE first, then intermediates, then root
        Collections.reverse(chain);

        // Convert BC private key to java.security.PrivateKey if present
        java.security.PrivateKey javaPrivateKey = null;
        AsymmetricKeyParameter bcPrivateKey = eeCertificate.getPrivateKey();

        if (bcPrivateKey != null && bcPrivateKey.isPrivate()) {
            try {
                PrivateKeyInfo pkInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(bcPrivateKey);
                javaPrivateKey = new JcaPEMKeyConverter().getPrivateKey(pkInfo);
            } catch (Exception e) {
                throw new RuntimeException("Failed to convert private key: " + e.getMessage(), e);
            }
        }

        // Create PKCS12 keystore
        KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
        char[] passwordChars = request.getPassword().toCharArray();

        // Initialize empty keystore
        pkcs12.load(null, passwordChars);

        String alias = "certificate-" + eeCertificate.getSerialNumber();

        if (javaPrivateKey != null) {
            // Create certificate chain array
            X509Certificate[] certChain = chain.toArray(new X509Certificate[0]);

            // Set key entry with private key and certificate chain
            pkcs12.setKeyEntry(alias, javaPrivateKey, passwordChars, certChain);
        } else {
            // No private key available, store only certificates
            // Store the end-entity certificate as the main entry
            pkcs12.setCertificateEntry(alias, chain.get(0));

            // Store the rest of the chain as additional certificates
            for (int i = 1; i < chain.size(); i++) {
                pkcs12.setCertificateEntry(alias + "-chain-" + i, chain.get(i));
            }
        }

        // Write keystore to byte array
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            pkcs12.store(baos, passwordChars);
            return baos.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PKCS12 file: " + e.getMessage(), e);
        }
    }

    // Helper method to get certificate with signing chain
    private Optional<Certificate> getCertificate(BigInteger serialNumber) {
        return db.getCertificatesRepository()
                .findBySerialNumberWithSigningCertificateAndSignedBy(serialNumber);
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

    @Transactional
    public void addCertificateToCaUser(rs.ac.uns.ftn.pki.certificates.dtos.AddCertificateToCaUserRequest req) {
        var user = db.getUserRepository()
                .findByIdWithCertificates(UUID.fromString(req.caUserId()))
                .orElseThrow(() -> new RuntimeException("User not found!"));

        BigInteger serial;
        try {
            serial = new BigInteger(req.newCertificateSerialNumber());
        } catch (NumberFormatException ex) {
            throw new RuntimeException("Invalid certificate serial number format: " + req.newCertificateSerialNumber(), ex);
        }

        var certificate = db.getCertificatesRepository()
                .findBySerialNumber(serial)
                .orElseThrow(() -> new RuntimeException("Certificate not found for serial: " + serial));

        user.getMyCertificates().add(certificate);
        db.getUserRepository().save(user);
    }

    // Your other existing methods remain unchanged...
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
                .toList();
        return valid.stream()
                .map(c -> CertificateResponse.createDto(c, getStatus(c).toString()))
                .collect(Collectors.toList());
    }

    // ... rest of your existing methods (getMyCertificates, getStatus, etc.)
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