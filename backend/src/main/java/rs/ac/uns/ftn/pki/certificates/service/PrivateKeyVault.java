package rs.ac.uns.ftn.pki.certificates.service;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import rs.ac.uns.ftn.pki.security.*;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.UUID;

@Service
public class PrivateKeyVault {
    private final OrgKeyStore orgKeys;
    private final AesGcm aes;
    private final JdbcTemplate jdbc;

    public PrivateKeyVault(OrgKeyStore orgKeys, AesGcm aes, JdbcTemplate jdbc) {
        this.orgKeys = orgKeys; this.aes = aes; this.jdbc = jdbc;
    }

    /** Upis šifrovanog PKCS#8 (DER) u private_keys za dati cert serial i org. */
    public void storeForCertificate(UUID orgId, BigInteger certSerial, AsymmetricKeyParameter privKeyParam) {
        try {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(privKeyParam);
            byte[] pkcs8 = pki.getEncoded();

            var ok = orgKeys.getOrCreateOrgKek(orgId.toString());
            byte[] iv = aes.randomIv();
            String alg = "AES-256-GCM";
            byte[] aad = ("org:"+orgId+"|serial:"+certSerial.toString(10)+"|alg:"+alg).getBytes();
            byte[] ct  = aes.encrypt(ok.key(), iv, pkcs8, aad);

            jdbc.update("""
    INSERT INTO private_keys(
        owner_org_id, cert_serial, key_version, alg, cek_salt, cek_iv, ciphertext
    ) VALUES (
        ?, ?, ?, ?, decode('','hex'), ?, ?
    )
    ON CONFLICT (cert_serial) DO UPDATE SET
      key_version = EXCLUDED.key_version,
      alg         = EXCLUDED.alg,
      cek_iv      = EXCLUDED.cek_iv,
      ciphertext  = EXCLUDED.ciphertext
    """,
                    orgId,                   // 1  owner_org_id
                    certSerial,              // 2  cert_serial
                    ok.version(),            // 3  key_version
                    alg,                     // 4  alg
                    iv,                      // 5  cek_iv
                    ct                       // 6  ciphertext
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to store encrypted private key", e);
        }
    }

    /** Čitanje (dekripcija) – vraća PKCS#8 DER. */
    public PrivateKey loadForCertificate(UUID orgId, BigInteger certSerial) {
        var row = jdbc.queryForMap(
                "SELECT key_version, alg, cek_iv, ciphertext FROM private_keys WHERE owner_org_id=? AND cert_serial=?",
                orgId, certSerial
        );
        int ver = (Integer) row.get("key_version");
        byte[] iv = (byte[]) row.get("cek_iv");
        byte[] ct = (byte[]) row.get("ciphertext");
        String alg = (String) row.get("alg");

        var ok = orgKeys.getOrCreateOrgKek(orgId.toString()); // dobije KEK (po default najnoviji)
        // Ako želiš striktno verzionisanje: izvuci konkretan orgKEK po ver (dodaš metodu u OrgKeyStore)
        byte[] aad = ("org:"+orgId+"|serial:"+certSerial.toString(10)+"|alg:"+alg).getBytes();
        byte[] pkcs8 = aes.decrypt(ok.key(), iv, ct, aad);

        try {
            var pki = org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(pkcs8);
            return new org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter()
                    .setProvider("BC")
                    .getPrivateKey(pki);
            // (or use KeyFactory shown in Option B)
        } catch (Exception e) {
            throw new RuntimeException("Failed to deserialize PKCS#8 from vault", e);
        }
    }
}

