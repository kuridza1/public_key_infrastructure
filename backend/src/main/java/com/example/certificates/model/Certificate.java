package com.example.certificates.model;


import com.example.users.model.User;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import com.example.buildingBlocks.BaseEntity;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.StringWriter;
import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.util.Base64;

@Entity
@Table(name = "certificates")
@Getter
@Setter
@NoArgsConstructor
public class Certificate extends BaseEntity {

    @NotNull
    @Column(nullable = false/*, unique = true*/) // uncomment unique if each serial is unique in your PKI
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
    private AsymmetricKeyParameter privateKey; // not persisted

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "signed_by_id", nullable = false)
    private User signedBy;

    // If you really need the FK column exposed separately, add:
    // @Column(name = "signed_by_id", insertable = false, updatable = false)
    // private UUID signedById;

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
        } catch (IllegalArgumentException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
