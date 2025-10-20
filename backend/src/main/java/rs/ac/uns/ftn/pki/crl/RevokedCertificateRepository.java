package rs.ac.uns.ftn.pki.crl;

import java.math.BigInteger;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.pki.crl.model.RevokedCertificate;

public interface RevokedCertificateRepository extends JpaRepository<RevokedCertificate, Long> {
    Optional<RevokedCertificate> findByCertificate_SerialNumber(BigInteger serialNumber);
}
