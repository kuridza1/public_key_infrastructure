package rs.ac.uns.ftn.pki.certificates.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.pki.certificates.dtos.*;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;
import rs.ac.uns.ftn.pki.users.model.Role;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.UUID;
import java.util.List;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    private final CertificateService certificateService;

    public CertificateController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('Admin','CaUser')")
    public ResponseEntity<?> issueCertificate(@RequestBody IssueCertificateRequest request,
                                              @RequestHeader("userId") String userId,
                                              @RequestHeader("role") String role) {
        try {
            boolean isAdmin = "Admin".equals(role);
            certificateService.createCertificate(request, isAdmin, userId, userId, null, null);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get-all")
    public ResponseEntity<List<CertificateResponse>> getAllCertificates() {
        return ResponseEntity.ok(certificateService.getAllCertificates());
    }

    @GetMapping("/get-all-valid-signing")
    public ResponseEntity<?> getAllValidSigningCertificates() {
        try {
            return ResponseEntity.ok(certificateService.getAllValidSigningCertificates());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get-signing-ca-doesnt-have/{caUserId}")
    @PreAuthorize("hasRole('Admin')")
    public ResponseEntity<?> getValidSigningCertificatesCaUserDoesntHave(@PathVariable String caUserId) {
        try {
            return ResponseEntity.ok(certificateService.getValidSigningCertificatesCaUserDoesntHave(caUserId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/add-certificate-to-ca-user")
    @PreAuthorize("hasRole('Admin')")
    public ResponseEntity<?> addCertificateToCaUser(@RequestBody AddCertificateToCaUserRequest request) {
        try {
            certificateService.addCertificateToCaUser(request);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get-my-certificates")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMyCertificates(@RequestHeader("userId") String userId) {
        try {
            return ResponseEntity.ok(certificateService.getMyCertificates(userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get-my-valid-certificates")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMyValidCertificates(@RequestHeader("userId") String userId) {
        try {
            return ResponseEntity.ok(certificateService.getMyValidCertificates(userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping("/get-certificates-signed-by-me")
    @PreAuthorize("hasRole('CaUser')")
    public ResponseEntity<?> getCertificatesSignedByMe(@RequestHeader("userId") String userId) {
        try {
            return ResponseEntity.ok(certificateService.getCertificatesSignedByMe(userId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/download")
    @PreAuthorize("hasAnyRole('Admin','CaUser','EeUser')")
    public ResponseEntity<?> downloadCertificate(@RequestBody DownloadCertificateRequest request,
                                                 @RequestHeader("userId") String userId,
                                                 @RequestHeader("role") String role) {
        try {
            Role parsedRole = Role.valueOf(role);
            byte[] pfxBytes = certificateService.getCertificateWithPasswordAsPkcs12(request, UUID.fromString(userId), parsedRole);

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=certificate_" + request.getCertificateSerialNumber() + ".pfx")
                    .body(pfxBytes);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}

