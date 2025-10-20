package rs.ac.uns.ftn.pki.crl.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.pki.crl.service.CrlService;
import rs.ac.uns.ftn.pki.crl.dtos.RevokeCertificateRequest;
import rs.ac.uns.ftn.pki.crl.dtos.RevokedCertificateResponse;
import rs.ac.uns.ftn.pki.users.model.Role;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/crl")
public class CrlController {

    private final CrlService crlService;

    public CrlController(CrlService crlService) {
        this.crlService = crlService;
    }

    @GetMapping("/web")
    public List<RevokedCertificateResponse> getAll() {
        return crlService.getAll();
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revokeCertificate(
            @RequestBody RevokeCertificateRequest req,
            @RequestHeader("X-Requester-Id") UUID requesterId,
            @RequestHeader("X-Requester-Role") Role requesterRole) {
        try {
            crlService.revokeCertificate(req, requesterId, requesterRole);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping(produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> downloadCrl() {
        try {
            byte[] file = crlService.getRevocationFile();
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"revoked_certs.crl\"")
                    .body(file);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage().getBytes());
        }
    }
}
