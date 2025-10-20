package rs.ac.uns.ftn.pki.crl.dtos;

import rs.ac.uns.ftn.pki.crl.model.RevocationReason;
import rs.ac.uns.ftn.pki.crl.model.RevokedCertificate;

public class RevokedCertificateResponse {

    private String serialNumber;
    private String prettySerialNumber;
    private String issuedBy;
    private String issuedTo;
    private String decryptedCertificate;
    private RevocationReason revocationReason;

    public RevokedCertificateResponse() {
    }

    public RevokedCertificateResponse(String serialNumber, String prettySerialNumber, String issuedBy,
                                      String issuedTo, String decryptedCertificate, RevocationReason revocationReason) {
        this.serialNumber = serialNumber;
        this.prettySerialNumber = prettySerialNumber;
        this.issuedBy = issuedBy;
        this.issuedTo = issuedTo;
        this.decryptedCertificate = decryptedCertificate;
        this.revocationReason = revocationReason;
    }

    public static RevokedCertificateResponse fromEntity(RevokedCertificate revokedCertificate) {
        return new RevokedCertificateResponse(
                revokedCertificate.getCertificate().getSerialNumber().toString(),
                CertificateResponse.convertToHexDisplay(revokedCertificate.getCertificate().getSerialNumber()),
                revokedCertificate.getCertificate().getIssuedBy(),
                revokedCertificate.getCertificate().getIssuedTo(),
                revokedCertificate.getCertificate().getPem(),
                revokedCertificate.getRevocationReason()
        );
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getPrettySerialNumber() {
        return prettySerialNumber;
    }

    public void setPrettySerialNumber(String prettySerialNumber) {
        this.prettySerialNumber = prettySerialNumber;
    }

    public String getIssuedBy() {
        return issuedBy;
    }

    public void setIssuedBy(String issuedBy) {
        this.issuedBy = issuedBy;
    }

    public String getIssuedTo() {
        return issuedTo;
    }

    public void setIssuedTo(String issuedTo) {
        this.issuedTo = issuedTo;
    }

    public String getDecryptedCertificate() {
        return decryptedCertificate;
    }

    public void setDecryptedCertificate(String decryptedCertificate) {
        this.decryptedCertificate = decryptedCertificate;
    }

    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(RevocationReason revocationReason) {
        this.revocationReason = revocationReason;
    }
}
