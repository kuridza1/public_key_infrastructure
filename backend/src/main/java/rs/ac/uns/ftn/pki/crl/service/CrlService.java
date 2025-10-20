package rs.ac.uns.ftn.pki.crl.service;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.repository.CertificateRepository;
import rs.ac.uns.ftn.pki.crl.repository.RevokedCertificateRepository;
import rs.ac.uns.ftn.pki.crl.dtos.RevokeCertificateRequest;
import rs.ac.uns.ftn.pki.crl.dtos.RevokedCertificateResponse;
import rs.ac.uns.ftn.pki.crl.model.RevocationReason;
import rs.ac.uns.ftn.pki.crl.model.RevokedCertificate;
import rs.ac.uns.ftn.pki.users.model.Role;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;


@Service
@Transactional
public class CrlService {

    private final RevokedCertificateRepository revokedRepo;
    private final CertificateRepository certRepo;
    private final UserRepository userRepo;
    private final PrivateKey signingKey;
    private final X509Certificate issuerCert;

    public CrlService(RevokedCertificateRepository revokedRepo,
                      CertificateRepository certRepo,
                      UserRepository userRepo,
                      PrivateKey crlSigningPrivateKey,
                      X509Certificate crlIssuerCertificate) {
        this.revokedRepo = revokedRepo;
        this.certRepo = certRepo;
        this.userRepo = userRepo;
        this.signingKey = crlSigningPrivateKey;
        this.issuerCert = crlIssuerCertificate;
    }

    @Transactional(readOnly = true)
    public List<RevokedCertificateResponse> getAll() {
        return revokedRepo.findAll()
                .stream()
                .map(RevokedCertificateResponse::fromEntity)
                .toList();
    }

    public void revokeCertificate(RevokeCertificateRequest req, UUID requesterId, Role requesterRole) {
        BigInteger serial = new BigInteger(req.getSerialNumber());
        Optional<Certificate> certOpt = certRepo.findBySerialNumber(serial);
        if (certOpt.isEmpty()){
            throw new IllegalArgumentException("Certificate not found!");
        }
        Certificate cert = certOpt.get();

        revokedRepo.findByCertificate_SerialNumber(serial)
                .ifPresent(r -> { throw new IllegalStateException("Certificate already revoked!"); });

        switch (requesterRole) {
            case CaUser -> {
                if (cert.getSignedBy() == null ||
                        !cert.getSignedBy().getId().equals(requesterId))
                    throw new IllegalStateException("A CA user can only revoke certificates signed by them!");
            }
            case EeUser -> {
                var user = userRepo.findWithMyCertificatesById(requesterId)
                        .orElseThrow(() -> new IllegalArgumentException("Requester user not found!"));
                if (!user.getMyCertificates().contains(cert))
                    throw new IllegalStateException("An EE user can only revoke certificates requested by them!");
            }
            default -> {}
        }

        RevokedCertificate entity = new RevokedCertificate();
        entity.setCertificate(cert);
        entity.setRevocationReason(req.getRevocationReason());
        revokedRepo.save(entity);
    }

    @Transactional(readOnly = true)
    public byte[] getRevocationFile() {
        Instant now = Instant.now();

        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuer, Date.from(now));
        builder.setNextUpdate(Date.from(now.plus(7, ChronoUnit.DAYS)));

        revokedRepo.findAll().forEach(rc -> {
            BigInteger sn = rc.getCertificate().getSerialNumber();
            int reason = mapReason(rc.getRevocationReason());
            builder.addCRLEntry(sn, Date.from(now), reason);
        });

        try {
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
            X509CRLHolder holder = builder.build(signer);
            return holder.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate CRL", e);
        }
    }

    private static int mapReason(RevocationReason r) {
        return switch (r) {
            case UNSPECIFIED -> CRLReason.unspecified;
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
        };
    }
}
