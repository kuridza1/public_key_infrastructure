package rs.ac.uns.ftn.pki.certRequests.dtos;

public class KeyPairDto {

    private String publicKey;
    private String privateKey;

    public KeyPairDto() {}

    public KeyPairDto(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}
