package rs.ac.uns.ftn.pki.crl.repository;

import java.math.BigInteger;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.pki.crl.model.RevokedCertificate;

public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    Optional<RevokedCertificate> findByCertificate_SerialNumber(BigInteger serialNumber);

    boolean existsRevokedCertificateByCertificateSerialNumber(BigInteger certificateSerialNumber);

    boolean existsByCertificateSerialNumber(BigInteger certificateSerialNumber);

    // If you want to fetch by certificate id instead:
    boolean existsByCertificate_Id(UUID certId);
}
