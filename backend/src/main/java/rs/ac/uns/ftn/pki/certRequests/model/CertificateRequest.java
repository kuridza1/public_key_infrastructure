package rs.ac.uns.ftn.pki.certRequests.model;

import jakarta.persistence.*;
import rs.ac.uns.ftn.pki.users.model.User;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_requests")
public class CertificateRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Use TEXT in DB (PostgreSQL) to prevent truncation on large CSRs
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

    public CertificateRequest() { }

    public CertificateRequest(String encodedCSR, User requestedFor, User requestedFrom,
                              LocalDateTime submittedOn, LocalDateTime notBefore, LocalDateTime notAfter) {
        this.encodedCSR = encodedCSR;
        this.requestedFor = requestedFor;
        this.requestedFrom = requestedFrom;
        this.submittedOn = submittedOn;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public Long getId() { return id; }
    public String getEncodedCSR() { return encodedCSR; }
    public void setEncodedCSR(String encodedCSR) { this.encodedCSR = encodedCSR; }
    public User getRequestedFor() { return requestedFor; }
    public void setRequestedFor(User requestedFor) { this.requestedFor = requestedFor; }
    public User getRequestedFrom() { return requestedFrom; }
    public void setRequestedFrom(User requestedFrom) { this.requestedFrom = requestedFrom; }
    public LocalDateTime getSubmittedOn() { return submittedOn; }
    public void setSubmittedOn(LocalDateTime submittedOn) { this.submittedOn = submittedOn; }
    public LocalDateTime getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDateTime notBefore) { this.notBefore = notBefore; }
    public LocalDateTime getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDateTime notAfter) { this.notAfter = notAfter; }

    /**
     * Normalize whatever was stored (PEM/JSON/CSV/Base64) into a clean Base64 DER string.
     */
    @Transient
    public String getEncodedCsrNormalized() {
        if (encodedCSR == null) return null;

        String s = encodedCSR.trim();

        // Unquote if CSV/JSON stored like: "MIIC..."
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"') {
            s = s.substring(1, s.length() - 1).trim();
        }

        // Unescape common JSON sequences (if they sneaked in)
        s = s.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t");

        // Strip PEM headers/footers if present
        s = s.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "");

        // Remove all whitespace
        s = s.replaceAll("\\s+", "");

        // URL-safe to standard Base64
        s = s.replace('-', '+').replace('_', '/');

        // Add Base64 padding if missing
        int mod = s.length() % 4;
        if (mod != 0) s = s + "====".substring(mod);

        return s;
    }
}
