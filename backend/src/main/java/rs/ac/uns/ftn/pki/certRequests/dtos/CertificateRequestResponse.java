package rs.ac.uns.ftn.pki.certRequests.dtos;

import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;

import java.time.LocalDateTime;
import java.util.Collection;


public class CertificateRequestResponse {

    private String id;
    private LocalDateTime submittedOn;
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String email;
    private String country;
    private LocalDateTime notBefore;
    private LocalDateTime notAfter;

    private Collection<KeyUsageValue> keyUsage;
    private Collection<ExtendedKeyUsageValue> extendedKeyUsage;
    private ListOfNames subjectAlternativeNames;
    private ListOfNames issuerAlternativeNames;
    private NamesConstraintsValue nameConstraints;
    private BasicConstraintsValue basicConstraints;
    private CertificatePolicy certificatePolicy;

    public CertificateRequestResponse() {}

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public LocalDateTime getSubmittedOn() { return submittedOn; }
    public void setSubmittedOn(LocalDateTime submittedOn) { this.submittedOn = submittedOn; }

    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }

    public String getOrganization() { return organization; }
    public void setOrganization(String organization) { this.organization = organization; }

    public String getOrganizationalUnit() { return organizationalUnit; }
    public void setOrganizationalUnit(String organizationalUnit) { this.organizationalUnit = organizationalUnit; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public LocalDateTime getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDateTime notBefore) { this.notBefore = notBefore; }

    public LocalDateTime getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDateTime notAfter) { this.notAfter = notAfter; }

    public Collection<KeyUsageValue> getKeyUsage() { return keyUsage; }
    public void setKeyUsage(Collection<KeyUsageValue> keyUsage) { this.keyUsage = keyUsage; }

    public Collection<ExtendedKeyUsageValue> getExtendedKeyUsage() { return extendedKeyUsage; }
    public void setExtendedKeyUsage(Collection<ExtendedKeyUsageValue> extendedKeyUsage) { this.extendedKeyUsage = extendedKeyUsage; }

    public ListOfNames getSubjectAlternativeNames() { return subjectAlternativeNames; }
    public void setSubjectAlternativeNames(ListOfNames subjectAlternativeNames) { this.subjectAlternativeNames = subjectAlternativeNames; }

    public ListOfNames getIssuerAlternativeNames() { return issuerAlternativeNames; }
    public void setIssuerAlternativeNames(ListOfNames issuerAlternativeNames) { this.issuerAlternativeNames = issuerAlternativeNames; }

    public NamesConstraintsValue getNameConstraints() { return nameConstraints; }
    public void setNameConstraints(NamesConstraintsValue nameConstraints) { this.nameConstraints = nameConstraints; }

    public BasicConstraintsValue getBasicConstraints() { return basicConstraints; }
    public void setBasicConstraints(BasicConstraintsValue basicConstraints) { this.basicConstraints = basicConstraints; }

    public CertificatePolicy getCertificatePolicy() { return certificatePolicy; }
    public void setCertificatePolicy(CertificatePolicy certificatePolicy) { this.certificatePolicy = certificatePolicy; }
}

