package rs.ac.uns.ftn.pki.certificates.model.keyManagement;

import rs.ac.uns.ftn.pki.buildingBlocks.BaseEntity;

public class MasterKey extends BaseEntity {
    private String encryptedKey;

    public MasterKey() {
        // Default constructor
    }

    public MasterKey(String encryptedKey) {
        this.encryptedKey = encryptedKey;
    }

    public String getEncryptedKey() {
        return encryptedKey;
    }

    public void setEncryptedKey(String encryptedKey) {
        this.encryptedKey = encryptedKey;
    }
}