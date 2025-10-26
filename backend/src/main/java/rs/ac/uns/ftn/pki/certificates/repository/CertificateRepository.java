package rs.ac.uns.ftn.pki.certificates.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;

import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, UUID> {

    // Query by serialNumber (BigInteger) — serialNumber is NOT the entity ID
    Optional<Certificate> findBySerialNumber(BigInteger serialNumber);

    // Same, but eager-fetch signingCertificate and signedBy
    @Query("""
        SELECT c FROM Certificate c
        LEFT JOIN FETCH c.signingCertificate
        LEFT JOIN FETCH c.signedBy
        WHERE c.serialNumber = :serialNumber
    """)
    Optional<Certificate> findBySerialNumberWithSigningCertificateAndSignedBy(
            @Param("serialNumber") BigInteger serialNumber);

    // All CA certificates
    List<Certificate> findByCanSignTrue();

    // All CA certificates that have a parent (non-root), with eager fetches
    @Query("""
        SELECT c FROM Certificate c
        LEFT JOIN FETCH c.signingCertificate
        LEFT JOIN FETCH c.signedBy
        WHERE c.canSign = true AND c.signingCertificate IS NOT NULL
    """)
    List<Certificate> findByCanSignWithSigningCertificate();

    // Certificates issued by user
    @Query("""
        SELECT c FROM Certificate c
        LEFT JOIN FETCH c.signedBy
        WHERE c.signedBy.id = :signedById
    """)
    List<Certificate> findBySignedById(@Param("signedById") UUID signedById);

    // Currently active time-window (does not check revocation)
    @Query("""
        SELECT c FROM Certificate c
        WHERE c.notBefore <= CURRENT_TIMESTAMP
          AND c.notAfter  >= CURRENT_TIMESTAMP
    """)
    List<Certificate> findActiveCertificates();

    // For listing active signing certs for an issuer while excluding revoked
    @Query("""
        SELECT c FROM Certificate c
        WHERE c.signedBy.id = :issuerId
          AND c.notBefore <= :now
          AND c.notAfter  >= :now
          AND c.canSign = true
          AND NOT EXISTS (
             SELECT 1 FROM RevokedCertificate r
             WHERE r.certificateSerialNumber = c.serialNumber
          )
    """)
    List<Certificate> findActiveSigningByIssuer(@Param("issuerId") UUID issuerId,
                                                @Param("now") OffsetDateTime now);

    // Self-signed (roots)
    List<Certificate> findBySigningCertificateIsNull();
}
