package rs.ac.uns.ftn.pki.crl.model;

import jakarta.persistence.*;
import java.io.Serializable;
import java.math.BigInteger;

import rs.ac.uns.ftn.pki.certificates.model.Certificate;

@Entity
@Table(
        name = "revoked_certificates",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_revoked_cert_serial",     columnNames = "certificate_serial_number"),
                @UniqueConstraint(name = "uk_revoked_cert_certificate", columnNames = "certificate_id")
        }
)
public class RevokedCertificate implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The revoked certificate entity.
     * LAZY to avoid loading heavy LOBs/relations when not needed.
     * No cascade — revoking must not persist/remove the Certificate itself.
     */
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "certificate_id", nullable = false)
    private Certificate certificate;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", nullable = false, length = 64)
    private RevocationReason revocationReason;

    /**
     * We persist the serial number as well so CRL creation can read serials
     * without touching the lazy Certificate relation.
     */
    @Column(name = "certificate_serial_number", nullable = false, unique = true)
    private BigInteger certificateSerialNumber;

    // --- ctors ---

    public RevokedCertificate() { }

    public RevokedCertificate(Certificate certificate,
                              RevocationReason revocationReason,
                              BigInteger certificateSerialNumber) {
        this.certificate = certificate;
        this.revocationReason = revocationReason;
        this.certificateSerialNumber = certificateSerialNumber;
    }

    // --- getters/setters ---

    public Long getId() {
        return id;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }

    public BigInteger getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public void setCertificateSerialNumber(BigInteger certificateSerialNumber) {
        this.certificateSerialNumber = certificateSerialNumber;
    }

    // --- helpers (optional) ---

    public static RevokedCertificate of(Certificate cert, RevocationReason reason) {
        return new RevokedCertificate(cert, reason, cert != null ? cert.getSerialNumber() : null);
    }

    @Override
    public String toString() {
        return "RevokedCertificate{" +
                "id=" + id +
                ", serial=" + certificateSerialNumber +
                ", reason=" + revocationReason +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RevokedCertificate that)) return false;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return 31;
    }
}
