package rs.ac.uns.ftn.pki.crl.dtos;


import rs.ac.uns.ftn.pki.crl.model.RevocationReason;

public class RevokeCertificateRequest {

    private String serialNumber;
    private RevocationReason revocationReason;

    public RevokeCertificateRequest() {
    }

    public RevokeCertificateRequest(String serialNumber, RevocationReason revocationReason) {
        this.serialNumber = serialNumber;
        this.revocationReason = revocationReason;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }
}
