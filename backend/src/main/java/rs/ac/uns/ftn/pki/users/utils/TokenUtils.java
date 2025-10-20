package rs.ac.uns.ftn.pki.users.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

public final class TokenUtils {
    private static final SecureRandom RNG = new SecureRandom();

    private TokenUtils() {}

    public static byte[] newSecureRandom(int bytes) {
        byte[] b = new byte[bytes];
        RNG.nextBytes(b);
        return b;
    }

    public static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data)).toUpperCase();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static String sha256Hex(String s) {
        return sha256Hex(s.getBytes(StandardCharsets.UTF_8));
    }
}
