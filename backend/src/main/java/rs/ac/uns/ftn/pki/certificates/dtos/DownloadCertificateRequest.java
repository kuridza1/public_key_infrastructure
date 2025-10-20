package rs.ac.uns.ftn.pki.certificates.dtos;

import java.util.Objects;

public class DownloadCertificateRequest {
    private final String certificateSerialNumber;
    private final String password;

    // Constructor
    public DownloadCertificateRequest(String certificateSerialNumber, String password) {
        this.certificateSerialNumber = certificateSerialNumber;
        this.password = password;
    }

    // Getters
    public String getCertificateSerialNumber() {
        return certificateSerialNumber;
    }

    public String getPassword() {
        return password;
    }

    // equals() method
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DownloadCertificateRequest that = (DownloadCertificateRequest) o;
        return Objects.equals(certificateSerialNumber, that.certificateSerialNumber) &&
                Objects.equals(password, that.password);
    }

    // hashCode() method
    @Override
    public int hashCode() {
        return Objects.hash(certificateSerialNumber, password);
    }

    // toString() method
    @Override
    public String toString() {
        return "DownloadCertificateRequest{" +
                "certificateSerialNumber='" + certificateSerialNumber + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}