package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;

import java.util.*;
import java.util.stream.Collectors;

public class ListOfNames {
    private String value;

    private static final Map<String, Integer> nameTypeMap;

    static {
        nameTypeMap = new HashMap<>();
        nameTypeMap.put("other", GeneralName.otherName);
        nameTypeMap.put("email", GeneralName.rfc822Name);
        nameTypeMap.put("dns", GeneralName.dNSName);
        nameTypeMap.put("uri", GeneralName.uniformResourceIdentifier);
        nameTypeMap.put("ip", GeneralName.iPAddress);
    }

    public ListOfNames() {}

    public ListOfNames(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    private List<GeneralName> parseGeneralNames() {
        if (value == null || value.trim().isEmpty()) {
            return new ArrayList<>();
        }

        String[] names = value.split(",");
        List<GeneralName> result = new ArrayList<>();

        for (String name : names) {
            String trimmedName = name.trim();
            if (trimmedName.isEmpty()) {
                continue;
            }

            String[] parts = trimmedName.split(":", 2);
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid name format: " + trimmedName);
            }

            String key = parts[0].trim();
            Integer nameType = nameTypeMap.get(key.toLowerCase());
            if (nameType == null) {
                throw new IllegalArgumentException("Unknown general name type: " + key);
            }

            result.add(new GeneralName(nameType, parts[1].trim()));
        }

        return result;
    }

    public GeneralName[] toGeneralNames() {
        List<GeneralName> names = parseGeneralNames();
        return names.toArray(new GeneralName[0]);
    }

    public List<GeneralSubtree> toGeneralSubtrees() {
        return parseGeneralNames().stream()
                .map(GeneralSubtree::new)
                .collect(Collectors.toList());
    }
}

class GeneralNamesExtensions {
    public static ListOfNames toListOfNames(GeneralNames generalNames) {
        StringBuilder sb = new StringBuilder();

        GeneralName[] names = generalNames.getNames();
        for (int i = 0; i < names.length; i++) {
            GeneralName gn = names[i];
            String prefix;

            switch (gn.getTagNo()) {
                case GeneralName.otherName:
                    prefix = "other";
                    break;
                case GeneralName.rfc822Name:
                    prefix = "email";
                    break;
                case GeneralName.dNSName:
                    prefix = "dns";
                    break;
                case GeneralName.uniformResourceIdentifier:
                    prefix = "uri";
                    break;
                case GeneralName.iPAddress:
                    prefix = "ip";
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported GeneralName tag: " + gn.getTagNo());
            }

            if (sb.length() > 0) {
                sb.append(',');
            }

            sb.append(prefix).append(':').append(gn.getName().toString());
        }

        return new ListOfNames(sb.toString());
    }
}