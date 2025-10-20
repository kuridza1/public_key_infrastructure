package rs.ac.uns.ftn.pki.certRequests.repository;


import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;


public interface CertificateRequestRepository extends JpaRepository<CertificateRequest, UUID> {

    // Load only requests submitted to this CA (requestedFrom)
    @EntityGraph(attributePaths = {"requestedFrom"}) // eager the CA if helpful
    List<CertificateRequest> findAllByRequestedFrom_Id(UUID requestedFromId);

    Optional<CertificateRequest> findById(UUID id);

    // For ownership-checked deletes (returns number of rows deleted)
    long deleteByIdAndRequestedFrom_Id(long id, UUID requestedFromId);
}
