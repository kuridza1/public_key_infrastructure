package rs.ac.uns.ftn.pki.security;

// src/main/java/.../security/OrgKeyStore.java
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

@Repository
public class OrgKeyStore {
    private final JdbcTemplate jdbc;
    private final AesGcm aes;
    private final MasterKeyProvider mkp;
    private final SecureRandom rnd = new SecureRandom();

    public OrgKeyStore(JdbcTemplate jdbc, AesGcm aes, MasterKeyProvider mkp) {
        this.jdbc = jdbc; this.aes = aes; this.mkp = mkp;
    }

    public OrgKek getOrCreateOrgKek(String orgId) {
        // pokušaj load
        var rows = jdbc.queryForList(
                "SELECT key_version, wrapped_key, iv, alg FROM org_keys WHERE org_id=? ORDER BY key_version DESC LIMIT 1",
                orgId
        );
        if (!rows.isEmpty()) {
            Map<String,Object> r = rows.get(0);
            int ver = (Integer) r.get("key_version");
            byte[] iv  = (byte[]) r.get("iv");
            byte[] w   = (byte[]) r.get("wrapped_key");
            byte[] kek = aes.decrypt(mkp.getMasterKeyForOrg(orgId), iv, w, ("org:"+orgId+"|v:"+ver).getBytes());
            return new OrgKek(ver, kek);
        }

        // kreiraj
        byte[] kek = new byte[32]; rnd.nextBytes(kek);
        int ver = 1;
        byte[] iv = aes.randomIv();
        byte[] aad = ("org:"+orgId+"|v:"+ver).getBytes();
        byte[] wrapped = aes.encrypt(mkp.getMasterKeyForOrg(orgId), iv, kek, aad);
        jdbc.update("INSERT INTO org_keys(org_id, key_version, wrapped_key, iv, alg) VALUES (?,?,?,?,?)",
                orgId, ver, wrapped, iv, "AES-256-GCM");
        return new OrgKek(ver, kek);
    }

    public record OrgKek(int version, byte[] key) {}
}
