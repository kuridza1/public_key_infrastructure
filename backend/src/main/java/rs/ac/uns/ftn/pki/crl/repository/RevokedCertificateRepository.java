package rs.ac.uns.ftn.pki.crl.repository;

import java.math.BigInteger;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.pki.crl.model.RevokedCertificate;

public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    Optional<RevokedCertificate> findByCertificate_SerialNumber(BigInteger serialNumber);

    boolean existsRevokedCertificateByCertificateSerialNumber(BigInteger certificateSerialNumber);
}
