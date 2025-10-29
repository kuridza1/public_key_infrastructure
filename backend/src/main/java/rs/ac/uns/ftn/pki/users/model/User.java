package rs.ac.uns.ftn.pki.users.model;

import rs.ac.uns.ftn.pki.buildingBlocks.BaseEntity;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;

import java.time.OffsetDateTime;
import java.util.*;

@Entity
@Table(name = "app_user", uniqueConstraints = {
        @UniqueConstraint(name = "uk_app_user_email", columnNames = "email")
})
public class User extends BaseEntity {

    @NotNull
    @Enumerated(EnumType.STRING)
    private Role role;

    @Size(max = 100)
    private String name;

    @Size(max = 100)
    private String surname;

    @Size(max = 150)
    private String organization;

    @NotBlank
    @Email
    @Column(nullable = false, unique = true)
    private String email;

    @NotNull
    private Boolean emailConfirmed;

    @NotBlank
    private String hashedPassword;

    @Column(length = 2048)
    private String refreshToken;

    private OffsetDateTime refreshTokenExpiresAt;

    /** Certificates this user ISSUED (inverse side; FK lives on Certificate.signedBy). */
    @OneToMany(mappedBy = "signedBy", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Certificate> issuedCertificates = new ArrayList<>();

    /** Certificates ASSIGNED to this user (ownership/usable by this CA). */
    @ManyToMany
    @JoinTable(
            name = "user_assigned_certificates",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "certificate_id")
    )
    private Set<Certificate> assignedCertificates = new HashSet<>();

    // --- Getters / Setters ---

    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSurname() { return surname; }
    public void setSurname(String surname) { this.surname = surname; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public Boolean getEmailConfirmed() { return emailConfirmed; }
    public void setEmailConfirmed(Boolean emailConfirmed) { this.emailConfirmed = emailConfirmed; }

    public String getHashedPassword() { return hashedPassword; }
    public void setHashedPassword(String hashedPassword) { this.hashedPassword = hashedPassword; }

    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }

    public OffsetDateTime getRefreshTokenExpiresAt() { return refreshTokenExpiresAt; }
    public void setRefreshTokenExpiresAt(OffsetDateTime refreshTokenExpiresAt) { this.refreshTokenExpiresAt = refreshTokenExpiresAt; }

    public List<Certificate> getIssuedCertificates() { return issuedCertificates; }
    public void setIssuedCertificates(List<Certificate> issuedCertificates) { this.issuedCertificates = issuedCertificates; }

    public Set<Certificate> getAssignedCertificates() { return assignedCertificates; }
    public void setAssignedCertificates(Set<Certificate> assignedCertificates) { this.assignedCertificates = assignedCertificates; }

    // --- Optional compatibility shim (keeps old code compiling) ---
    /** @deprecated Use getIssuedCertificates() instead. */
    @Deprecated
    @Transient
    public List<Certificate> getMyCertificates() { return issuedCertificates; }

    /** @deprecated Use setIssuedCertificates(...) instead. */
    @Deprecated
    @Transient
    public void setMyCertificates(List<Certificate> certs) { this.issuedCertificates = certs; }
}
