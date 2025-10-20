package rs.ac.uns.ftn.pki.certificates.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AesEncryption {

    public static byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    public static String encrypt(String plainText, byte[] key, byte[] iv) throws Exception {
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = encrypt(plainBytes, key, iv);

        // prepend IV to encrypted data (same as C#)
        byte[] combined = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static String decrypt(String cipherBase64, byte[] key) throws Exception {
        byte[] allBytes = Base64.getDecoder().decode(cipherBase64);

        // first 16 bytes = IV
        byte[] iv = new byte[16];
        System.arraycopy(allBytes, 0, iv, 0, 16);

        byte[] cipherBytes = new byte[allBytes.length - 16];
        System.arraycopy(allBytes, 16, cipherBytes, 0, cipherBytes.length);

        byte[] plainBytes = decrypt(cipherBytes, key, iv);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }
}
