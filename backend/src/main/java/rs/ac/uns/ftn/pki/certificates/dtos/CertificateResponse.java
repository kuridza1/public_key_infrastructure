package rs.ac.uns.ftn.pki.certificates.dtos;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record CertificateResponse(
        String serialNumber,
        String prettySerialNumber,
        String issuedBy,
        String issuedTo,
        LocalDateTime validFrom,
        LocalDateTime validUntil,
        String status,
        String decryptedCertificate,
        boolean canSign,
        int pathLen
) {
    public static CertificateResponse createDto(Certificate c, String status) {
        return new CertificateResponse(
                c.getSerialNumber().toString(),
                convertToHexDisplay(c.getSerialNumber()),
                extractX509Values(c.getIssuedBy()),
                extractX509Values(c.getIssuedTo()),
                c.getNotBefore().toLocalDateTime(),
                c.getNotAfter().toLocalDateTime(),
                status,
                c.getPem(),
                c.getCanSign(),
                c.getPathLen()
        );
    }

    public static String convertToHexDisplay(BigInteger number) {
        byte[] bytes = number.toByteArray();

        // Remove leading zero byte if present (BigInteger adds this for sign)
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        // Reverse for big-endian display
        byte[] reversed = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            reversed[i] = bytes[bytes.length - 1 - i];
        }

        int desiredLength = 16;
        if (reversed.length < desiredLength) {
            byte[] padded = new byte[desiredLength];
            Arrays.fill(padded, (byte) 0x00);
            System.arraycopy(reversed, 0, padded, desiredLength - reversed.length, reversed.length);
            reversed = padded;
        }

        // Convert to hex string with colons
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < reversed.length; i++) {
            if (i > 0) {
                sb.append(":");
            }
            sb.append(String.format("%02X", reversed[i]));
        }
        return sb.toString();
    }

    private static String extractX509Values(String dn) {
        try {
            X509Name x = new X509Name(dn);
            List<String> lines = new ArrayList<>();

            // Common Name line
            String cn = getFirstValue(x, X509Name.CN);
            if (cn != null) {
                lines.add(cn);
            }

            // Organization line
            List<String> orgParts = new ArrayList<>();
            String o = getFirstValue(x, X509Name.O);
            String ou = getFirstValue(x, X509Name.OU);
            if (o != null) orgParts.add(o);
            if (ou != null) orgParts.add(ou);
            if (!orgParts.isEmpty()) {
                lines.add(String.join(", ", orgParts));
            }

            // Location line
            List<String> locParts = new ArrayList<>();
            String l = getFirstValue(x, X509Name.L);
            String st = getFirstValue(x, X509Name.ST);
            String c = getFirstValue(x, X509Name.C);
            if (l != null) locParts.add(l);
            if (st != null) locParts.add(st);
            if (c != null) locParts.add(c);
            if (!locParts.isEmpty()) {
                lines.add(String.join(", ", locParts));
            }

            return String.join("\n", lines);
        } catch (Exception e) {
            return dn; // Fallback to original DN if parsing fails
        }
    }

    private static String getFirstValue(X509Name x509Name, ASN1ObjectIdentifier oid) {
        try {
            Vector<?> values = x509Name.getValues(oid);
            if (values != null && !values.isEmpty()) {
                Object firstValue = values.get(0);
                return firstValue != null ? firstValue.toString() : null;
            }
        } catch (Exception e) {
            // Value not found for this OID
        }
        return null;
    }
}