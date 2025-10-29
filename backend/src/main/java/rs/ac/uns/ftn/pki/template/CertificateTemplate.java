package rs.ac.uns.ftn.pki.template;

import org.hibernate.annotations.GenericGenerator;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.users.model.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "certificate_templates")
public class CertificateTemplate {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @NotBlank
    @Column(nullable = false, length = 255)
    private String name;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_issuer_id", nullable = false)
    private Certificate caIssuer;

    @Column(name = "common_name_regex", length = 500)
    private String commonNameRegex;

    @Column(name = "san_regex", length = 500)
    private String sanRegex;

    @Column(name = "max_ttl_days")
    private Integer maxTtlDays;

    @Column(name = "key_usage", length = 500)
    private String keyUsage;

    @Column(name = "extended_key_usage", length = 500)
    private String extendedKeyUsage;

    @Column(name = "basic_constraints", length = 100)
    private String basicConstraints;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by", nullable = false)
    private User createdBy;

    @NotNull
    @Column(nullable = false)
    private LocalDateTime createdAt;

    public CertificateTemplate() {
        this.createdAt = LocalDateTime.now();
    }

    // Getters and setters...
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Certificate getCaIssuer() { return caIssuer; }
    public void setCaIssuer(Certificate caIssuer) { this.caIssuer = caIssuer; }
    public String getCommonNameRegex() { return commonNameRegex; }
    public void setCommonNameRegex(String commonNameRegex) { this.commonNameRegex = commonNameRegex; }
    public String getSanRegex() { return sanRegex; }
    public void setSanRegex(String sanRegex) { this.sanRegex = sanRegex; }
    public Integer getMaxTtlDays() { return maxTtlDays; }
    public void setMaxTtlDays(Integer maxTtlDays) { this.maxTtlDays = maxTtlDays; }
    public String getKeyUsage() { return keyUsage; }
    public void setKeyUsage(String keyUsage) { this.keyUsage = keyUsage; }
    public String getExtendedKeyUsage() { return extendedKeyUsage; }
    public void setExtendedKeyUsage(String extendedKeyUsage) { this.extendedKeyUsage = extendedKeyUsage; }
    public String getBasicConstraints() { return basicConstraints; }
    public void setBasicConstraints(String basicConstraints) { this.basicConstraints = basicConstraints; }
    public User getCreatedBy() { return createdBy; }
    public void setCreatedBy(User createdBy) { this.createdBy = createdBy; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}