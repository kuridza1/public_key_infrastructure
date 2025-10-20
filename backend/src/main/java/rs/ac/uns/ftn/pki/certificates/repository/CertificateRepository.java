package rs.ac.uns.ftn.pki.certificates.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, BigInteger> {

    // Find certificate by serial number with signing certificate and signed by user eagerly loaded
    @Query("SELECT c FROM Certificate c " +
            "LEFT JOIN FETCH c.signingCertificate " +
            "LEFT JOIN FETCH c.signedBy " +
            "WHERE c.serialNumber = :serialNumber")
    Optional<Certificate> findByIdWithSigningCertificateAndSignedBy(@Param("serialNumber") BigInteger serialNumber);

    // Find all certificates that can sign (CA certificates)
    List<Certificate> findByCanSignTrue();

    Optional<Certificate> findBySerialNumber(BigInteger serialNumber);

    // Find all certificates that can sign and have a signing certificate (non-root CAs)
    @Query("SELECT c FROM Certificate c " +
            "LEFT JOIN FETCH c.signingCertificate " +
            "LEFT JOIN FETCH c.signedBy " +
            "WHERE c.canSign = true AND c.signingCertificate IS NOT NULL")
    List<Certificate> findByCanSignWithSigningCertificate();

    // Find certificates signed by a specific user
    @Query("SELECT c FROM Certificate c " +
            "LEFT JOIN FETCH c.signedBy " +
            "WHERE c.signedBy.id = :signedById")
    List<Certificate> findBySignedById(@Param("signedById") UUID signedById);

    // Find active certificates (not expired, not revoked, etc.)
    @Query("SELECT c FROM Certificate c " +
            "WHERE c.notBefore <= CURRENT_TIMESTAMP " +
            "AND c.notAfter >= CURRENT_TIMESTAMP")
    List<Certificate> findActiveCertificates();

    // Find certificates that are about to expire (within X days)
    @Query("SELECT c FROM Certificate c " +
            "WHERE c.notAfter BETWEEN CURRENT_TIMESTAMP AND :expiryThreshold")
    List<Certificate> findCertificatesExpiringSoon(@Param("expiryThreshold") java.time.LocalDateTime expiryThreshold);

    // Find root certificates (self-signed)
    List<Certificate> findBySigningCertificateIsNull();

    // Find certificates by common name (partial match)
    List<Certificate> findBySubjectCommonNameContainingIgnoreCase(String commonName);

    // Find certificates by organization
    List<Certificate> findBySubjectOrganization(String organization);


    @Query("""
        select c from Certificate c
        where c.signedBy.id = :issuerId
          and c.notBefore <= :now
          and c.notAfter  >= :now
          and c.canSign = true
          and not exists (
             select 1 from RevokedCertificate r
             where r.certificateSerialNumber = c.serialNumber
          )
        """)
    List<Certificate> findActiveSigningByIssuer(UUID issuerId, LocalDateTime now);
}