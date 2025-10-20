package rs.ac.uns.ftn.pki.certificates.model.keyManagement;

import java.util.UUID;

public class UserKey {
    private UUID userId;
    private String encryptedKey;

    public UserKey() {
        // Default constructor
    }

    public UserKey(UUID userId, String encryptedKey) {
        this.userId = userId;
        this.encryptedKey = encryptedKey;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(String encryptedKey) {
        this.encryptedKey = encryptedKey;
    }
}