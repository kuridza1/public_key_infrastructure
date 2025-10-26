package rs.ac.uns.ftn.pki.certRequests.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import rs.ac.uns.ftn.pki.certRequests.dtos.*;
import rs.ac.uns.ftn.pki.certRequests.service.CertificateRequestService;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

@RestController
@RequestMapping("/api/certificate-requests")
public class CertificateRequestController {

    private final CertificateRequestService certificateRequestService;

    public CertificateRequestController(CertificateRequestService certificateRequestService) {
        this.certificateRequestService = certificateRequestService;
    }

    // ---------------------------------------------------------
    // POST /form  →  EE user creates a CSR via form (returns PEM keypair)
    // ---------------------------------------------------------
    @PostMapping("/form")
    @PreAuthorize("hasRole('EeUser')")
    public ResponseEntity<?> createFromForm(@RequestBody CreateCertificateRequestDTO request,
                                            @RequestHeader("userId") String userId) {
        try {
            KeyPairDto keyPair = certificateRequestService.createCertificateRequest(request, userId);
            return ResponseEntity.ok(keyPair);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // POST /csr  →  EE user uploads an existing CSR file
    // ---------------------------------------------------------
    @PostMapping(value = "/csr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('EeUser')")
    public ResponseEntity<?> uploadCsr(
            @RequestParam("csrFile") MultipartFile csrFile,
            @RequestParam("signingOrganization") String signingOrganization,
            @RequestParam(value = "notAfter", required = false) String notAfterStr,
            @RequestHeader("userId") String userId
    ) {
        try {
            if (csrFile == null || csrFile.isEmpty() || signingOrganization == null || signingOrganization.isBlank())
                return ResponseEntity.badRequest().body("Missing required fields!");

            // Read PEM CSR content
            StringBuilder contentBuilder = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(csrFile.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    contentBuilder.append(line).append("\n");
                }
            }

            String csrContent = contentBuilder.toString();
            LocalDateTime notAfter = null;
            if (notAfterStr != null && !notAfterStr.isBlank()) {
                Instant instant = Instant.parse(notAfterStr);
                notAfter = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            }

            certificateRequestService.createCertificateRequest(signingOrganization, csrContent, notAfter, userId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // GET /  →  CA user gets all requests addressed to them
    // ---------------------------------------------------------
    @GetMapping
    @PreAuthorize("hasRole('CaUser')")
    public ResponseEntity<?> getRequests(@RequestHeader("userId") String userId) {
        try {
            List<CertificateRequestResponse> requests = certificateRequestService.getCertificateRequests(userId);
            return ResponseEntity.ok(requests);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // POST /reject  →  CA user deletes a pending certificate request
    // ---------------------------------------------------------
    @PostMapping("/reject")
    @PreAuthorize("hasRole('CaUser')")
    public ResponseEntity<?> rejectRequest(@RequestBody String requestId,
                                           @RequestHeader("userId") String userId) {
        try {
            certificateRequestService.deleteCertificateRequest(userId, requestId);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // POST /approve  →  CA user approves and signs a certificate request
    // ---------------------------------------------------------
    @PostMapping("/approve")
    @PreAuthorize("hasRole('CaUser')")
    public ResponseEntity<?> approveRequest(@RequestBody ApproveCertificateRequest approveRequest,
                                            @RequestHeader("userId") String userId) {
        try {
            certificateRequestService.approveCertificateRequest(userId, approveRequest);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
