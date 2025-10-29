package rs.ac.uns.ftn.pki.security;

// src/main/java/.../security/AesGcm.java
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;
import java.security.SecureRandom;

@Component
public class AesGcm {
    private static final String TRANS = "AES/GCM/NoPadding";
    private static final int TAG_BITS = 128;
    private final SecureRandom rnd = new SecureRandom();

    public byte[] randomIv() {
        byte[] iv = new byte[12]; // 96-bit nonce
        rnd.nextBytes(iv);
        return iv;
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(TRANS);
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(plaintext);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(TRANS);
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(ciphertext);
        } catch (Exception e) { throw new RuntimeException(e); }
    }
}
