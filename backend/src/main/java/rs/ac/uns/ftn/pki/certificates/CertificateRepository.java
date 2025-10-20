package rs.ac.uns.ftn.pki.certificates;

import java.math.BigInteger;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(BigInteger serialNumber);
}
