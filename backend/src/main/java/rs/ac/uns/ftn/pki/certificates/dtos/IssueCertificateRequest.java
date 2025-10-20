package rs.ac.uns.ftn.pki.certificates.dtos;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;

import java.time.LocalDateTime;
import java.util.*;

public record IssueCertificateRequest(
        String signingCertificate,
        String commonName,
        String organization,
        String organizationalUnit,
        String email,
        String country,
        LocalDateTime notBefore,
        LocalDateTime notAfter,
        Collection<KeyUsageValue> keyUsage,
        Collection<ExtendedKeyUsageValue> extendedKeyUsage,
        ListOfNames subjectAlternativeNames,
        ListOfNames issuerAlternativeNames,
        NamesConstraintsValue nameConstraints,
        BasicConstraintsValue basicConstraints,
        CertificatePolicy certificatePolicy
) {
    public X509Name getX509Name() {
        // Using the order-aware constructor with Vector
        Vector<ASN1ObjectIdentifier> oids = new Vector<>();
        Vector<String> values = new Vector<>();

        // Add required Common Name
        oids.add(X509Name.CN);
        values.add(commonName);

        // Add optional fields if not empty
        addOptionalField(oids, values, X509Name.O, organization);
        addOptionalField(oids, values, X509Name.OU, organizationalUnit);
        addOptionalField(oids, values, X509Name.EmailAddress, email);
        addOptionalField(oids, values, X509Name.C, country);

        return new X509Name(oids, values);
    }

    private void addOptionalField(Vector<ASN1ObjectIdentifier> oids, Vector<String> values,
                                  ASN1ObjectIdentifier oid, String value) {
        if (value != null && !value.trim().isEmpty()) {
            oids.add(oid);
            values.add(value);
        }
    }
}