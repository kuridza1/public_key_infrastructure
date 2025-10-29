package rs.ac.uns.ftn.pki.template;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;
import rs.ac.uns.ftn.pki.users.model.User;

import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Service
@Transactional
public class CertificateTemplateService {

    private final CertificateTemplateRepository templateRepository;

    @Lazy
    @Autowired
    private CertificateService certificateService;

    public CertificateTemplateService(CertificateTemplateRepository templateRepository) {
        this.templateRepository = templateRepository;
    }

    public CertificateTemplate createTemplate(CertificateTemplate template, User creator) {
        // Validate that CA issuer exists and belongs to creator's organization
        Certificate caIssuer = template.getCaIssuer();
        if (caIssuer == null) {
            throw new RuntimeException("CA issuer is required");
        }

        // Validate that CA issuer is actually a CA certificate
        if (!caIssuer.getCanSign()) {
            throw new RuntimeException("Selected certificate is not a CA certificate");
        }

        // Check if template name already exists in organization
        if (templateRepository.existsByNameAndOrganization(template.getName(), creator.getOrganization())) {
            throw new RuntimeException("Template with this name already exists in your organization");
        }

        // Validate regex patterns
        if (template.getCommonNameRegex() != null && !isValidRegex(template.getCommonNameRegex())) {
            throw new RuntimeException("Invalid Common Name regex pattern");
        }

        if (template.getSanRegex() != null && !isValidRegex(template.getSanRegex())) {
            throw new RuntimeException("Invalid SAN regex pattern");
        }

        template.setCreatedBy(creator);
        return templateRepository.save(template);
    }

    public List<CertificateTemplate> getTemplatesForUser(User user) {
        if (user.getRole().name().equals("Admin")) {
            // Admin can see all templates
            return templateRepository.findAll();
        } else {
            // CA users can only see templates from their organization
            return templateRepository.findByOrganization(user.getOrganization());
        }
    }

    public List<CertificateTemplate> getTemplatesForCaCertificate(UUID caId, User user) {
        // Security check - user can only access templates for their organization's CA certificates
        List<CertificateTemplate> templates = templateRepository.findUsableTemplates(caId, user.getOrganization());

        // Filter by organization if user is not admin
        if (!user.getRole().name().equals("Admin")) {
            templates = templates.stream()
                    .filter(template -> template.getCaIssuer().getIssuedTo().contains(user.getOrganization()))
                    .toList();
        }

        return templates;
    }

    public CertificateTemplate updateTemplate(UUID templateId, CertificateTemplate updatedTemplate, User user) {
        CertificateTemplate existing = templateRepository.findById(templateId)
                .orElseThrow(() -> new RuntimeException("Template not found"));

        // Security check - user can only update templates from their organization
        if (!user.getRole().name().equals("Admin") &&
                !existing.getCaIssuer().getIssuedTo().contains(user.getOrganization())) {
            throw new RuntimeException("You can only update templates from your organization");
        }

        // Update allowed fields
        existing.setCommonNameRegex(updatedTemplate.getCommonNameRegex());
        existing.setSanRegex(updatedTemplate.getSanRegex());
        existing.setMaxTtlDays(updatedTemplate.getMaxTtlDays());
        existing.setKeyUsage(updatedTemplate.getKeyUsage());
        existing.setExtendedKeyUsage(updatedTemplate.getExtendedKeyUsage());
        existing.setBasicConstraints(updatedTemplate.getBasicConstraints());

        return templateRepository.save(existing);
    }

    public void deleteTemplate(UUID templateId, User user) {
        CertificateTemplate template = templateRepository.findById(templateId)
                .orElseThrow(() -> new RuntimeException("Template not found"));

        // Security check
        if (!user.getRole().name().equals("Admin") &&
                !template.getCaIssuer().getIssuedTo().contains(user.getOrganization())) {
            throw new RuntimeException("You can only delete templates from your organization");
        }

        templateRepository.delete(template);
    }

    public boolean validateAgainstTemplate(CertificateTemplate template, String commonName, String san) {
        // Validate Common Name against regex
        if (template.getCommonNameRegex() != null && !template.getCommonNameRegex().isEmpty()) {
            if (!commonName.matches(template.getCommonNameRegex())) {
                return false;
            }
        }

        // Validate SAN against regex
        if (template.getSanRegex() != null && !template.getSanRegex().isEmpty() && san != null) {
            if (!san.matches(template.getSanRegex())) {
                return false;
            }
        }

        return true;
    }

    public void validateTemplateUsage(CertificateTemplate template, User user) {
        // Provera da li korisnik ima pravo da koristi šablon
        if (!user.getRole().name().equals("Admin") &&
                !template.getCaIssuer().getIssuedTo().contains(user.getOrganization())) {
            throw new RuntimeException("Template does not belong to your organization");
        }

        // Provera da li je CA issuer i dalje validan
        var status = certificateService.getStatus(template.getCaIssuer());
        if (status != rs.ac.uns.ftn.pki.certificates.model.CertificateStatus.ACTIVE) {
            throw new RuntimeException("CA issuer is not active (status: " + status + ")");
        }
    }

    private boolean isValidRegex(String regex) {
        if (regex == null || regex.trim().isEmpty()) {
            return true;
        }
        try {
            Pattern.compile(regex);
            return true;
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
}