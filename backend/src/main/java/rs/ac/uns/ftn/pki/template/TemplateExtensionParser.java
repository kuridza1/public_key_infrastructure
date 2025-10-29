package rs.ac.uns.ftn.pki.template;

import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class TemplateExtensionParser {

    public static Collection<KeyUsageValue> parseKeyUsage(String keyUsageString) {
        if (keyUsageString == null || keyUsageString.trim().isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.stream(keyUsageString.split("\\s*,\\s*"))
                .map(String::trim)
                .map(TemplateExtensionParser::toKeyUsageValue)
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static Collection<ExtendedKeyUsageValue> parseExtendedKeyUsage(String extendedKeyUsageString) {
        if (extendedKeyUsageString == null || extendedKeyUsageString.trim().isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.stream(extendedKeyUsageString.split("\\s*,\\s*"))
                .map(String::trim)
                .map(TemplateExtensionParser::toExtendedKeyUsageValue)
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static BasicConstraintsValue parseBasicConstraints(String basicConstraintsString) {
        if (basicConstraintsString == null || basicConstraintsString.trim().isEmpty()) {
            return null;
        }

        // Parse format: "CA:true,pathlen:0"
        // Implementation depends on your BasicConstraintsValue structure
        // This is a simplified example
        boolean ca = basicConstraintsString.contains("CA:true");
        Integer pathLen = extractPathLen(basicConstraintsString);

        return new BasicConstraintsValue(ca, pathLen);
    }

    private static KeyUsageValue toKeyUsageValue(String usage) {
        try {
            return KeyUsageValue.valueOf(usage.trim());
        } catch (IllegalArgumentException e) {
            return null; // or handle error appropriately
        }
    }

    private static ExtendedKeyUsageValue toExtendedKeyUsageValue(String usage) {
        try {
            return ExtendedKeyUsageValue.valueOf(usage.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Integer extractPathLen(String constraints) {
        // Extract pathlen value from string
        // Simple implementation - adjust as needed
        if (constraints.contains("pathlen:")) {
            try {
                String[] parts = constraints.split("pathlen:");
                if (parts.length > 1) {
                    String lenStr = parts[1].split("[,\\s]")[0];
                    return Integer.parseInt(lenStr);
                }
            } catch (NumberFormatException e) {
                // Log error
            }
        }
        return null;
    }
}