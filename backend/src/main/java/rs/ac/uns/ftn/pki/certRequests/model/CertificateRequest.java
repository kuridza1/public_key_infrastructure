package rs.ac.uns.ftn.pki.certRequests.model;

import jakarta.persistence.*;
import rs.ac.uns.ftn.pki.users.model.User;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.stream.Collectors;

@Entity
@Table(name = "certificate_requests")
public class CertificateRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "encoded_csr", nullable = false, columnDefinition = "TEXT")
    private String encodedCSR;

    @ManyToOne(optional = false)
    @JoinColumn(name = "requested_for_id", nullable = false)
    private User requestedFor;

    @ManyToOne(optional = false)
    @JoinColumn(name = "requested_from_id", nullable = false)
    private User requestedFrom;

    @Column(name = "submitted_on", nullable = false)
    private LocalDateTime submittedOn;

    @Column(name = "not_before")
    private LocalDateTime notBefore;

    @Column(name = "not_after")
    private LocalDateTime notAfter;

    // Constructors
    public CertificateRequest() {}

    public CertificateRequest(String encodedCSR, User requestedFor, User requestedFrom,
                              LocalDateTime submittedOn, LocalDateTime notBefore, LocalDateTime notAfter) {
        this.encodedCSR = encodedCSR;
        this.requestedFor = requestedFor;
        this.requestedFrom = requestedFrom;
        this.submittedOn = submittedOn;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    // Getter and Setter methods
    public Long getId() {
        return id;
    }

    public String getEncodedCSR() {
        return encodedCSR;
    }

    public void setEncodedCSR(String encodedCSR) {
        this.encodedCSR = encodedCSR;
    }

    public User getRequestedFor() {
        return requestedFor;
    }

    public void setRequestedFor(User requestedFor) {
        this.requestedFor = requestedFor;
    }

    public User getRequestedFrom() {
        return requestedFrom;
    }

    public void setRequestedFrom(User requestedFrom) {
        this.requestedFrom = requestedFrom;
    }

    public LocalDateTime getSubmittedOn() {
        return submittedOn;
    }

    public void setSubmittedOn(LocalDateTime submittedOn) {
        this.submittedOn = submittedOn;
    }

    public LocalDateTime getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(LocalDateTime notBefore) {
        this.notBefore = notBefore;
    }

    public LocalDateTime getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(LocalDateTime notAfter) {
        this.notAfter = notAfter;
    }

    // Equivalent of GetEncodedCsrNoHeader()
    public String getEncodedCsrNoHeader() {
        if (encodedCSR == null) return null;

        return Arrays.stream(encodedCSR.split("\n"))
                .filter(line -> !line.contains("CERTIFICATE"))
                .map(String::trim)
                .collect(Collectors.joining());
    }
}
