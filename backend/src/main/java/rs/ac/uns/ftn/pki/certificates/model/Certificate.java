package rs.ac.uns.ftn.pki.certificates.model;

import rs.ac.uns.ftn.pki.users.model.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import rs.ac.uns.ftn.pki.buildingBlocks.BaseEntity;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.StringWriter;
import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.time.chrono.ChronoLocalDateTime;
import java.util.Base64;

@Entity
@Table(name = "certificates")
public class Certificate extends BaseEntity {

    @NotNull
    @Column(nullable = false)
    private BigInteger serialNumber;

    @ManyToOne(fetch = FetchType.LAZY, optional = true)
    @JoinColumn(name = "signing_certificate_id")
    private Certificate signingCertificate;

    @NotBlank
    @Column(nullable = false, length = 255)
    private String issuedBy;

    @NotBlank
    @Column(nullable = false, length = 255)
    private String issuedTo;

    @NotNull
    @Column(nullable = false)
    private OffsetDateTime notBefore;

    @NotNull
    @Column(nullable = false)
    private OffsetDateTime notAfter;

    @NotBlank
    @Lob
    @Column(nullable = false)
    private String encodedValue; // Base64-encoded DER (X.509)

    @NotNull
    @Column(nullable = false)
    private Boolean canSign;

    @Min(0)
    @Column(nullable = false)
    private int pathLen;

    @Transient
    private AsymmetricKeyParameter privateKey;

    @ManyToOne(optional = true, fetch = FetchType.LAZY)
    @JoinColumn(
            name = "signed_by_id",
            referencedColumnName = "id",
            foreignKey = @ForeignKey(name = "fk_cert_signed_by")
    )
    private User signedBy;

    public Certificate() {
    }

    // --- Getters and Setters ---

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public Certificate getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(Certificate signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    public String getIssuedTo() {
        return issuedTo;
    }

    public void setIssuedTo(String issuedTo) {
        this.issuedTo = issuedTo;
    }

    public OffsetDateTime getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(OffsetDateTime notBefore) {
        this.notBefore = notBefore;
    }

    public OffsetDateTime getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(OffsetDateTime notAfter) {
        this.notAfter = notAfter;
    }

    public String getEncodedValue() {
        return encodedValue;
    }

    public void setEncodedValue(String encodedValue) {
        this.encodedValue = encodedValue;
    }

    public Boolean getCanSign() {
        return canSign;
    }

    public void setCanSign(Boolean canSign) {
        this.canSign = canSign;
    }

    public int getPathLen() {
        return pathLen;
    }

    public void setPathLen(int pathLen) {
        this.pathLen = pathLen;
    }

    public AsymmetricKeyParameter getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(AsymmetricKeyParameter privateKey) {
        this.privateKey = privateKey;
    }

    public User getSignedBy() {
        return signedBy;
    }

    public void setSignedBy(User signedBy) {
        this.signedBy = signedBy;
    }

    // --- PEM Conversion Helpers ---
    @Transient
    public String getPem() {
        if (encodedValue == null || encodedValue.isBlank()) {
            return "Certificate is empty!";
        }
        String pem = toPem(encodedValue);
        return pem != null ? pem : "Malformed certificate";
    }

    private static String toPem(String base64) {
        try {
            byte[] bytes = Base64.getDecoder().decode(base64);
            StringWriter sw = new StringWriter();
            try (PemWriter pw = new PemWriter(sw)) {
                pw.writeObject(new PemObject("CERTIFICATE", bytes));
            }
            return sw.toString();
        } catch (Exception e) {
            return null;
        }
    }
}
