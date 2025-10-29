package rs.ac.uns.ftn.pki.template;
import java.util.UUID;

public record TemplateResponse(
        UUID id,
        String name,
        String caIssuerName,
        String commonNameRegex,
        String sanRegex,
        Integer maxTtlDays,
        String keyUsage,
        String extendedKeyUsage,
        String basicConstraints,
        String createdBy,
        String createdAt
) {}