package rs.ac.uns.ftn.pki.certRequests.utils;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class CsrBytes {
    private CsrBytes() {}

    /** Normalize a stored CSR string (PEM/Base64/quoted) to DER bytes. */
    public static byte[] extract(String raw) {
        if (raw == null) throw new IllegalArgumentException("CSR is null");
        String s = raw.trim();

        // Strip surrounding quotes:  "MIIC..." -> MIIC...
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length()-1) == '"') {
            s = s.substring(1, s.length()-1).trim();
        }

        // If PEM, read directly
        if (s.contains("-----BEGIN")) {
            return assertDer(readPemToDer(s));
        }

        // Clean Base64 (remove whitespace, allow URL-safe, add padding)
        s = s.replaceAll("\\s+", "").replace('-', '+').replace('_', '/');
        int mod = s.length() % 4; if (mod != 0) s += "====".substring(mod);

        byte[] der = Base64.getDecoder().decode(s);

        // If decoded bytes are actually PEM text, parse them
        String asText = new String(der, StandardCharsets.US_ASCII);
        if (asText.startsWith("-----BEGIN")) {
            der = readPemToDer(asText);
        }
        return assertDer(der);
    }

    private static byte[] readPemToDer(String pem) {
        try (PemReader pr = new PemReader(new StringReader(pem))) {
            PemObject po = pr.readPemObject();
            if (po == null) throw new IllegalArgumentException("PEM parse failed: empty");
            return po.getContent();
        } catch (Exception e) {
            throw new IllegalArgumentException("PEM parse failed: " + e.getMessage(), e);
        }
    }

    private static byte[] assertDer(byte[] der) {
        if (der == null || der.length < 2 || (der[0] & 0xFF) != 0x30) { // ASN.1 SEQUENCE
            throw new IllegalArgumentException("Not DER SEQUENCE (len=" + (der == null ? 0 : der.length) + ")");
        }
        return der;
    }
}
