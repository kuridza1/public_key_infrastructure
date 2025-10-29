package rs.ac.uns.ftn.pki.template;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;
import rs.ac.uns.ftn.pki.dbContext.IUnifiedDbContext;

import java.math.BigInteger;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/templates")
public class CertificateTemplateController {

    private final CertificateTemplateService templateService;
    private final CertificateService certificateService;
    private final IUnifiedDbContext db;

    public CertificateTemplateController(CertificateTemplateService templateService,
                                         IUnifiedDbContext db,
                                         CertificateService certificateService) {
        this.templateService = templateService;
        this.certificateService = certificateService;
        this.db = db;
    }

    @PostMapping
    //@PreAuthorize("hasAnyRole('Admin','CaUser')")
    public ResponseEntity<?> createTemplate(@RequestBody CreateTemplateRequest request,
                                            @RequestHeader("userId") String userId) {
        try {
            var user = db.getUserRepository().findById(UUID.fromString(userId))
                    .orElseThrow(() -> new RuntimeException("User not found"));
            if (request.caIssuerId() == null || request.caIssuerId().isBlank()) {
                throw new RuntimeException("CA issuer ID is missing");
            }

            BigInteger serialNumber;
            try {
                serialNumber = new BigInteger(request.caIssuerId());
            } catch (NumberFormatException e) {
                throw new RuntimeException("Invalid CA issuer ID: " + request.caIssuerId(), e);
            }

            var caIssuer = db.getCertificatesRepository()
                    .findBySerialNumber(serialNumber)
                    .orElseThrow(() -> new RuntimeException("CA issuer not found"));


            CertificateTemplate template = new CertificateTemplate();
            template.setName(request.name());
            template.setCaIssuer(caIssuer);
            template.setCommonNameRegex(request.commonNameRegex());
            template.setSanRegex(request.sanRegex());
            template.setMaxTtlDays(request.maxTtlDays());
            template.setKeyUsage(request.keyUsage());
            template.setExtendedKeyUsage(request.extendedKeyUsage());
            template.setBasicConstraints(request.basicConstraints());

            CertificateTemplate created = templateService.createTemplate(template, user);
            return ResponseEntity.ok(toResponse(created));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public List<TemplateResponse> getUserTemplates(@RequestHeader("userId") String userId) {
        var user = db.getUserRepository().findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        return templateService.getTemplatesForUser(user).stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    @GetMapping("/ca/{caId}")
    @PreAuthorize("isAuthenticated()")
    public List<TemplateResponse> getTemplatesForCa(@PathVariable UUID caId,
                                                    @RequestHeader("userId") String userId) {
        var user = db.getUserRepository().findById(UUID.fromString(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));

        return templateService.getTemplatesForCaCertificate(caId, user).stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    private TemplateResponse toResponse(CertificateTemplate template) {
        return new TemplateResponse(
                template.getId(),
                template.getName(),
                template.getCaIssuer().getIssuedTo(),
                template.getCommonNameRegex(),
                template.getSanRegex(),
                template.getMaxTtlDays(),
                template.getKeyUsage(),
                template.getExtendedKeyUsage(),
                template.getBasicConstraints(),
                template.getCreatedBy().getEmail(),
                template.getCreatedAt().toString()
        );
    }

    @PostMapping("/issue")
    @PreAuthorize("hasAnyRole('Admin','CaUser')")
    public ResponseEntity<?> issueCertificate(@RequestBody IssueCertificateRequest request,
                                              @RequestHeader("userId") String caUserId,
                                              @RequestHeader(value = "X-Requesting-User-Id", required = false) String requestingUserId) {
        try {
            if (requestingUserId == null || requestingUserId.isBlank()) {
                return ResponseEntity.badRequest().body("Missing X-Requesting-User-Id header");
            }

            // Ensure both users exist before calling service
            db.getUserRepository().findById(UUID.fromString(caUserId))
                    .orElseThrow(() -> new RuntimeException("CA user not found"));
            db.getUserRepository().findById(UUID.fromString(requestingUserId))
                    .orElseThrow(() -> new RuntimeException("Requesting user not found"));

            // Create certificate using template
            certificateService.createCertificateWithTemplate(request, caUserId, requestingUserId, null, null);

            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
