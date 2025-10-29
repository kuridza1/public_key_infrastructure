package rs.ac.uns.ftn.pki.template;
import java.util.UUID;

public record CreateTemplateRequest(
        String name,
        String caIssuerId,
        String commonNameRegex,
        String sanRegex,
        Integer maxTtlDays,
        String keyUsage,
        String extendedKeyUsage,
        String basicConstraints
) {}
