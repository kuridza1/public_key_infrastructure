package rs.ac.uns.ftn.pki.certificates.dtos;

import java.util.Objects;

public final class AddCertificateToCaUserRequest {
    private final String caUserId;
    private final String newCertificateSerialNumber;

    public AddCertificateToCaUserRequest(String caUserId, String newCertificateSerialNumber) {
        this.caUserId = caUserId;
        this.newCertificateSerialNumber = newCertificateSerialNumber;
    }

    public String caUserId() {
        return caUserId;
    }

    public String newCertificateSerialNumber() {
        return newCertificateSerialNumber;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (AddCertificateToCaUserRequest) obj;
        return Objects.equals(this.caUserId, that.caUserId) &&
                Objects.equals(this.newCertificateSerialNumber, that.newCertificateSerialNumber);
    }

    @Override
    public int hashCode() {
        return Objects.hash(caUserId, newCertificateSerialNumber);
    }

    @Override
    public String toString() {
        return "AddCertificateToCaUserRequest[" +
                "caUserId=" + caUserId + ", " +
                "newCertificateSerialNumber=" + newCertificateSerialNumber + ']';
    }
}