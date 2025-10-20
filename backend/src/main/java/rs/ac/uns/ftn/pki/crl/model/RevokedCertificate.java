package rs.ac.uns.ftn.pki.crl.model;

import jakarta.persistence.*;
import java.math.BigInteger;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;

@Entity
@Table(name = "revoked_certificates")
public class RevokedCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(optional = false, cascade = CascadeType.ALL)
    @JoinColumn(name = "certificate_id", nullable = false)
    private Certificate certificate;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", nullable = false)
    private RevocationReason revocationReason;

    @Column(name = "certificate_serial_number", nullable = false, unique = true)
    private BigInteger certificateSerialNumber;

    // Constructors
    public RevokedCertificate() {
    }

    public RevokedCertificate(Certificate certificate, RevocationReason revocationReason, BigInteger certificateSerialNumber) {
        this.certificate = certificate;
        this.revocationReason = revocationReason;
        this.certificateSerialNumber = certificateSerialNumber;
    }

    // Getters and Setters
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
}
