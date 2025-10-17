package rs.ac.uns.ftn.pki.users.utils;

import org.springframework.core.io.Resource;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

public class FileCommonPasswordStore implements ICommonPasswordStore {

    private final Set<String> set;
    private final boolean normalizeToLower;

    public FileCommonPasswordStore(Resource resource, boolean normalizeToLower) throws Exception {
        if (resource == null || !resource.exists()) {
            throw new java.io.FileNotFoundException("Common password list not found: " + resource);
        }

        this.normalizeToLower = normalizeToLower;
        this.set = new HashSet<>();

        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                String s = line.trim();
                if (!s.isEmpty()) {
                    set.add(normalizeToLower ? s.toLowerCase() : s);
                }
            }
        }
    }

    public FileCommonPasswordStore(Resource resource) throws Exception {
        this(resource, true);
    }

    @Override
    public boolean contains(String candidate) {
        if (candidate == null || candidate.isEmpty()) return false;
        String c = normalizeToLower ? candidate.toLowerCase() : candidate;
        return set.contains(c);
    }
}
