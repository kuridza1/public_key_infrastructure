package rs.ac.uns.ftn.pki.certRequests;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import rs.ac.uns.ftn.pki.certRequests.dtos.ApproveCertificateRequest;
import rs.ac.uns.ftn.pki.certRequests.dtos.CertificateRequestResponse;
import rs.ac.uns.ftn.pki.certRequests.dtos.CreateCertificateRequestDTO;
import rs.ac.uns.ftn.pki.certRequests.dtos.KeyPairDto;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;
import rs.ac.uns.ftn.pki.certRequests.utils.CertificateRequestBuilder;
import rs.ac.uns.ftn.pki.certRequests.utils.CertificateRequestDecoder;
import rs.ac.uns.ftn.pki.certificates.model.CertificateStatus;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.users.model.Role;
import rs.ac.uns.ftn.pki.users.model.User;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;

@Service
@Transactional
public class CertificateRequestService {

    private final CertificateRequestRepository requestRepo;
    private final UserRepository userRepo;
    private final CertificateService certificateService;

    public CertificateRequestService(CertificateRequestRepository requestRepo,
                                     UserRepository userRepo,
                                     CertificateService certificateService) {
        this.requestRepo = requestRepo;
        this.userRepo = userRepo;
        this.certificateService = certificateService;
    }

    /**
     * Generates a subject RSA keypair, builds CSR with requested extensions,
     * validates issuer constraints, persists the request, and returns PEM keys.
     */
    public KeyPairDto createCertificateRequest(CreateCertificateRequestDTO dto, String userIdStr) {
        UUID userId = UUID.fromString(userIdStr);

        // EE user making the request
        User eeUser = userRepo.findByIdAndRole(userId, Role.EeUser)
                .orElseThrow(() -> new IllegalArgumentException("EE user not found!"));

        // Generate RSA keypair (subject keys)
        KeyPairGenerator kpGen;
        try {
            kpGen = KeyPairGenerator.getInstance("RSA");
            kpGen.initialize(2048, new SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("Unable to initialize RSA generator", e);
        }
        KeyPair subjectKeyPair = kpGen.generateKeyPair();

        // Issuer (CA) selected via dto.signingOrganization (CA user id)
        UUID issuerId = UUID.fromString(dto.getSigningOrganization());
        User issuer = userRepo.findWithMyCertificatesByIdAndRole(issuerId, Role.CaUser)
                .orElseThrow(() -> new IllegalArgumentException("Requested issuer is not found!"));

        // Verify issuer is able to sign (has at least one ACTIVE certificate)
        boolean hasActive = issuer.getMyCertificates() != null &&
                issuer.getMyCertificates().stream()
                        .anyMatch(c -> certificateService.getStatus(c) == CertificateStatus.ACTIVE);

        if (!hasActive) {
            throw new IllegalStateException("Requested issuer is not able to sign certificates!");
        }

        // Check requested validity against issuer's active cert validity range
        LocalDateTime minValidFrom = issuer.getMyCertificates().stream()
                .filter(c -> certificateService.getStatus(c, null) == CertificateStatus.ACTIVE)
                .map(Certificate::getNotBefore)
                .filter(Objects::nonNull)
                .min(LocalDateTime::compareTo)
                .orElse(null);

        LocalDateTime maxValidUntil = issuer.getMyCertificates().stream()
                .filter(c -> certificateService.getStatus(c, null) == CertificateStatus.ACTIVE)
                .map(Certificate::getNotAfter)
                .filter(Objects::nonNull)
                .max(LocalDateTime::compareTo)
                .orElse(null);

        if (dto.getNotBefore() != null && minValidFrom != null && dto.getNotBefore().isBefore(minValidFrom)) {
            throw new IllegalArgumentException("NotBefore cannot be earlier than the issuer's earliest NotBefore!");
        }
        if (dto.getNotAfter() != null && maxValidUntil != null && dto.getNotAfter().isAfter(maxValidUntil)) {
            throw new IllegalArgumentException("NotAfter cannot be later than the issuer's latest NotAfter!");
        }
        if (dto.getNotBefore() != null && dto.getNotAfter() != null && dto.getNotBefore().isAfter(dto.getNotAfter())) {
            throw new IllegalArgumentException("NotBefore cannot be later than the NotAfter!");
        }

        // Build CSR + persist request
        CertificateRequest entity = CertificateRequestBuilder.createCertificateRequest(dto, subjectKeyPair, issuer, eeUser);
        requestRepo.save(entity);

        // Return PEM public/private key strings
        return new KeyPairDto(pemOf(subjectKeyPair.getPublic()), pemOf(subjectKeyPair.getPrivate()));
    }

    /**
     * Stores a CSR provided by client (without generating keys).
     */
    public void createCertificateRequest(String signingUserId, String csr, LocalDateTime notAfter, String userIdStr) {
        UUID userId = UUID.fromString(userIdStr);
        UUID issuerId = UUID.fromString(signingUserId);

        User eeUser = userRepo.findByIdAndRole(userId, Role.EeUser)
                .orElseThrow(() -> new IllegalArgumentException("EE user not found!"));

        User issuer = userRepo.findWithMyCertificatesByIdAndRole(issuerId, Role.CaUser)
                .orElseThrow(() -> new IllegalArgumentException("Requested issuer is not found!"));

        boolean hasActive = issuer.getMyCertificates() != null &&
                issuer.getMyCertificates().stream()
                        .anyMatch(c -> certificateService.getStatus(c) == CertificateStatus.ACTIVE);

        if (!hasActive) throw new IllegalStateException("Requested issuer is not able to sign certificates!");

        LocalDateTime maxValidUntil = issuer.getMyCertificates().stream()
                .filter(c -> certificateService.getStatus(c, null) == CertificateStatus.ACTIVE)
                .map(Certificate::getNotAfter)
                .filter(Objects::nonNull)
                .max(LocalDateTime::compareTo)
                .orElse(null);

        if (notAfter != null && maxValidUntil != null && notAfter.isAfter(maxValidUntil)) {
            throw new IllegalArgumentException("NotAfter cannot be later than the issuer's latest NotAfter!");
        }

        CertificateRequest cr = new CertificateRequest();
        cr.setRequestedFor(eeUser);
        cr.setRequestedFrom(issuer);
        cr.setEncodedCSR(csr);
        cr.setNotAfter(notAfter);
        cr.setSubmittedOn(LocalDateTime.now());
        requestRepo.save(cr);
    }

    /**
     * Returns decoded CSR info for all requests submitted to the CA user.
     */
    @Transactional(readOnly = true)
    public List<CertificateRequestResponse> getCertificateRequests(String userIdStr) {
        UUID caId = UUID.fromString(userIdStr);
        // Ensure requester is CA
        userRepo.findByIdAndRole(caId, Role.CaUser)
                .orElseThrow(() -> new IllegalArgumentException("CA user not found!"));

        return requestRepo.findAllByRequestedFrom_Id(caId)
                .stream()
                .map(CertificateRequestDecoder::decodeCertificateRequest)
                .toList();
    }

    /**
     * Deletes a request if it belongs to the CA user.
     */
    public void deleteCertificateRequest(String userIdStr, String requestIdStr) {
        UUID caId = UUID.fromString(userIdStr);
        UUID reqId = UUID.fromString(requestIdStr);

        userRepo.findByIdAndRole(caId, Role.CaUser)
                .orElseThrow(() -> new IllegalArgumentException("CA user not found!"));

        long deleted = requestRepo.deleteByIdAndRequestedFrom_Id(reqId, caId);
        if (deleted == 0) {
            throw new IllegalStateException("Unable to delete certificate request with given ID (or not yours)!");
        }
        if (deleted > 1) {
            throw new IllegalStateException("Found multiple certificate requests with given ID!");
        }
    }

    /**
     * Issues a certificate from a stored CSR and removes the request.
     */
    public void approveCertificateRequest(String userIdStr, ApproveCertificateRequest approveRequest) {
        UUID caId = UUID.fromString(userIdStr);
        UUID reqId = UUID.fromString(approveRequest.getRequestId());

        User ca = userRepo.findByIdAndRole(caId, Role.CaUser)
                .orElseThrow(() -> new IllegalArgumentException("CA user not found!"));

        CertificateRequest req = requestRepo.findById(reqId)
                .orElseThrow(() -> new IllegalArgumentException("Certificate request with given ID not found!"));

        if (!req.getRequestedFrom().getId().equals(ca.getId())) {
            throw new IllegalStateException("This certificate is not requested from you!");
        }

        try {
            byte[] csrBytes = Base64.getDecoder().decode(req.getEncodedCsrNoHeader());
            PublicKey publicKey = new JcaPKCS10CertificationRequest(new PKCS10CertificationRequest(csrBytes))
                    .getPublicKey();

            certificateService.createCertificate(
                    approveRequest.getRequestForm(),
                    false,
                    userIdStr,
                    req.getRequestedFor().getId().toString(),
                    publicKey
            );

            // delete after successful issue
            deleteCertificateRequest(userIdStr, approveRequest.getRequestId());
        } catch (Exception e) {
            throw new RuntimeException("Failed to approve certificate request", e);
        }
    }

    // ----- helpers -----
    private static String pemOf(Object keyOrCert) {
        try (StringWriter sw = new StringWriter();
             JcaPEMWriter pem = new JcaPEMWriter(sw)) {
            pem.writeObject(keyOrCert);
            pem.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert to PEM", e);
        }
    }
}
