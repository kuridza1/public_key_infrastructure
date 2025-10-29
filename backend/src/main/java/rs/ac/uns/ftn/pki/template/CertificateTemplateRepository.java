package rs.ac.uns.ftn.pki.template;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.template.CertificateTemplate;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, UUID> {

    // Find all templates for a specific organization
    @Query("SELECT ct FROM CertificateTemplate ct WHERE ct.caIssuer.issuedTo LIKE %:organization%")
    List<CertificateTemplate> findByOrganization(@Param("organization") String organization);

    // Find templates by CA issuer certificate
    List<CertificateTemplate> findByCaIssuer_Id(UUID caIssuerId);

    // Find templates created by a specific user
    List<CertificateTemplate> findByCreatedBy_Id(UUID userId);

    // Find templates by organization and CA issuer
    @Query("SELECT ct FROM CertificateTemplate ct WHERE ct.caIssuer.issuedTo LIKE %:organization% AND ct.caIssuer.id = :caIssuerId")
    List<CertificateTemplate> findByOrganizationAndCaIssuer(@Param("organization") String organization,
                                                            @Param("caIssuerId") UUID caIssuerId);

    // Check if template name exists within organization
    @Query("SELECT COUNT(ct) > 0 FROM CertificateTemplate ct WHERE ct.name = :name AND ct.caIssuer.issuedTo LIKE %:organization%")
    boolean existsByNameAndOrganization(@Param("name") String name, @Param("organization") String organization);

    // Find templates that can be used with a specific CA certificate
    @Query("SELECT ct FROM CertificateTemplate ct WHERE ct.caIssuer.id = :caId AND ct.caIssuer.issuedTo LIKE %:organization%")
    List<CertificateTemplate> findUsableTemplates(@Param("caId") UUID caId, @Param("organization") String organization);


}