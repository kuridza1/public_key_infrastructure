package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;

import java.util.*;
import java.util.stream.Collectors;

public class ListOfNames {

    /**
     * Comma-separated list of general names in the format:
     *   dns:example.com, ip:192.168.1.10, email:user@example.com, uri:https://example.com
     * Supported prefixes: other, email, dns, uri, ip[, dir]
     */
    private String value;

    private static final Map<String, Integer> NAME_TYPE_MAP;
    private static final Map<Integer, String> TAG_PREFIX_MAP;

    static {
        Map<String, Integer> tmp = new HashMap<>();
        tmp.put("other", GeneralName.otherName);
        tmp.put("email", GeneralName.rfc822Name);
        tmp.put("dns", GeneralName.dNSName);
        tmp.put("uri", GeneralName.uniformResourceIdentifier);
        tmp.put("ip", GeneralName.iPAddress);
        // Uncomment if you want to support X.500 DNs inside SANs:
        // tmp.put("dir", GeneralName.directoryName);
        NAME_TYPE_MAP = Collections.unmodifiableMap(tmp);

        Map<Integer, String> rev = new HashMap<>();
        rev.put(GeneralName.otherName, "other");
        rev.put(GeneralName.rfc822Name, "email");
        rev.put(GeneralName.dNSName, "dns");
        rev.put(GeneralName.uniformResourceIdentifier, "uri");
        rev.put(GeneralName.iPAddress, "ip");
        // rev.put(GeneralName.directoryName, "dir");
        TAG_PREFIX_MAP = Collections.unmodifiableMap(rev);
    }

    public ListOfNames() {}

    public ListOfNames(String value) { this.value = value; }

    public String getValue() { return value; }

    public void setValue(String value) { this.value = value; }

    /** Parse the comma-separated value into GeneralName objects. */
    private List<GeneralName> parseGeneralNames() {
        if (value == null || value.trim().isEmpty()) return Collections.emptyList();

        String[] tokens = value.split(",");
        List<GeneralName> out = new ArrayList<>(tokens.length);

        for (String token : tokens) {
            String trimmed = token.trim();
            if (trimmed.isEmpty()) continue;

            String[] parts = trimmed.split(":", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("Invalid general name fragment (expected <type>:<value>): " + trimmed);
            }

            String key = parts[0].trim().toLowerCase(Locale.ROOT);
            String v = parts[1].trim();
            Integer tag = NAME_TYPE_MAP.get(key);
            if (tag == null) {
                throw new IllegalArgumentException("Unknown general name type: " + key + " in fragment: " + trimmed);
            }

            out.add(new GeneralName(tag, v));
        }
        return out;
    }

    /** Convert to array for APIs that expect GeneralName[]. */
    public GeneralName[] toGeneralNames() {
        List<GeneralName> names = parseGeneralNames();
        return names.toArray(new GeneralName[0]);
    }

    /** Convenience: return a GeneralNames object directly (most BC APIs accept this). */
    public GeneralNames toGeneralNamesObj() {
        return new GeneralNames(toGeneralNames());
    }

    /** Convert to GeneralSubtree list (used by NameConstraints). */
    public List<GeneralSubtree> toGeneralSubtrees() {
        return parseGeneralNames().stream().map(GeneralSubtree::new).collect(Collectors.toList());
    }

    /** Factory: build ListOfNames from a GeneralNames object (round-trippable to the same value format). */
    public static ListOfNames fromGeneralNames(GeneralNames generalNames) {
        if (generalNames == null || generalNames.getNames() == null) return new ListOfNames("");

        StringBuilder sb = new StringBuilder();
        GeneralName[] names = generalNames.getNames();
        for (int i = 0; i < names.length; i++) {
            GeneralName gn = names[i];

            String prefix = TAG_PREFIX_MAP.get(gn.getTagNo());
            if (prefix == null) {
                throw new IllegalArgumentException("Unsupported GeneralName tag: " + gn.getTagNo());
            }

            if (sb.length() > 0) sb.append(',');
            ASN1Encodable nameVal = gn.getName();
            sb.append(prefix).append(':').append(nameVal.toString());
        }
        return new ListOfNames(sb.toString());
    }
}
