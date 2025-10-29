package rs.ac.uns.ftn.pki.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;

@Component
public class FileMasterKeyProvider implements MasterKeyProvider {

    private final Path baseDir;
    private final String inlineB64; // optional spring property fallback

    public FileMasterKeyProvider(
            @Value("${pki.master.dir}") String dir,
            @Value("${pki.master.keyB64:}") String inlineB64
    ) {
        this.baseDir = Path.of(dir).toAbsolutePath().normalize();
        this.inlineB64 = (inlineB64 == null ? "" : inlineB64.trim());
    }

    @Override
    public byte[] getMasterKeyForOrg(String orgIdRaw) {
        String orgId = normalize(orgIdRaw);

        StringBuilder tried = new StringBuilder();

        // 1–3) direct orgId files
        for (String ext : new String[]{".b64", ".key", ".txt"}) {
            Path p = baseDir.resolve(orgId + ext);
            byte[] key = tryReadKey(p, tried);
            if (key != null) return key;
        }

        // 4) aliases.json mapping (UUID → alias like "org-001")
        Path aliasesPath = baseDir.resolve("aliases.json");
        if (Files.exists(aliasesPath)) {
            try {
                Map<String, String> aliases = new ObjectMapper()
                        .readValue(Files.readString(aliasesPath), Map.class);
                String alias = aliases.get(orgId);
                if (alias != null && !alias.isBlank()) {
                    String aliasId = normalize(alias);
                    for (String ext : new String[]{".b64", ".key", ".txt"}) {
                        Path p = baseDir.resolve(aliasId + ext);
                        byte[] key = tryReadKey(p, tried);
                        if (key != null) return key;
                    }
                } else {
                    tried.append("aliases.json present but no entry for ").append(orgId).append("\n");
                }
            } catch (Exception e) {
                tried.append("failed reading aliases.json: ").append(e.getMessage()).append("\n");
            }
        } else {
            tried.append("aliases.json not found\n");
        }

        // 5) default.b64
        Path defaultPath = baseDir.resolve("default.b64");
        byte[] def = tryReadKey(defaultPath, tried);
        if (def != null) return def;

        // 6) env PKI_MASTER_KEY_B64
        String envB64 = System.getenv("PKI_MASTER_KEY_B64");
        if (envB64 != null && !envB64.isBlank()) {
            byte[] k = decodeAndValidate(envB64.trim(), "env PKI_MASTER_KEY_B64", tried);
            if (k != null) return k;
        } else {
            tried.append("env PKI_MASTER_KEY_B64 not set\n");
        }

        // 7) spring prop pki.master.keyB64
        if (!inlineB64.isBlank()) {
            byte[] k = decodeAndValidate(inlineB64, "spring pki.master.keyB64", tried);
            if (k != null) return k;
        } else {
            tried.append("spring pki.master.keyB64 not set\n");
        }

        throw new RuntimeException("Cannot load master key for org " + orgId +
                ". Tried:\n" + tried);
    }

    private static String normalize(String s) {
        return (s == null ? "" : s.trim().toLowerCase());
    }

    private byte[] tryReadKey(Path p, StringBuilder tried) {
        try {
            if (!Files.exists(p)) {
                tried.append("missing ").append(p).append("\n");
                return null;
            }
            String b64 = Files.readString(p).trim();
            return decodeAndValidate(b64, p.toString(), tried);
        } catch (Exception e) {
            tried.append("error reading ").append(p).append(": ").append(e.getMessage()).append("\n");
            return null;
        }
    }

    private byte[] decodeAndValidate(String b64, String source, StringBuilder tried) {
        try {
            byte[] key = Base64.getDecoder().decode(b64);
            if (key.length != 32) {
                tried.append("invalid length from ").append(source)
                        .append(" (").append(key.length).append(" bytes)\n");
                return null;
            }
            return key;
        } catch (Exception e) {
            tried.append("invalid base64 from ").append(source)
                    .append(": ").append(e.getMessage()).append("\n");
            return null;
        }
    }
}
