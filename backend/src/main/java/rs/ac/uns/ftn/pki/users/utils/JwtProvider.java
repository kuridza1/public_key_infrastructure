package rs.ac.uns.ftn.pki.users.utils;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.users.model.User;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;

@Component
public class JwtProvider {

    @Value("${auth.jwt.p12.path}")
    private Resource keystoreResource;                 // <— handles classpath:/ file:/ etc.

    @Value("${auth.jwt.p12.password}")
    private String storePassword;

    // allow different key password; falls back to store password if not set
    @Value("${auth.jwt.key.password:${auth.jwt.p12.password}}")
    private String keyPassword;

    // optional; if blank we auto-pick the first PrivateKeyEntry
    @Value("${auth.jwt.p12.alias:}")
    private String alias;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    @PostConstruct
    void init() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream is = keystoreResource.getInputStream()) {
            ks.load(is, storePassword.toCharArray());
        }
        String useAlias = resolveAlias(ks, alias);
        this.privateKey = (PrivateKey) ks.getKey(useAlias, keyPassword.toCharArray());
        X509Certificate cert = (X509Certificate) ks.getCertificate(useAlias);
        this.publicKey = cert.getPublicKey();
    }

    private static String resolveAlias(KeyStore ks, String preferred) throws Exception {
        if (preferred != null && !preferred.isBlank()) return preferred;
        Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        throw new IllegalStateException("No PrivateKey entry found in PKCS#12 keystore.");
    }

    public record TokenResult(String jwt, OffsetDateTime exp) {}
    public record RefreshValidation(boolean ok, UUID userId, String reason) {}

    public TokenResult issueAccess(User u, String issuer, String audience, int minutes) {
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime exp = now.plusMinutes(minutes);
        String jwt = Jwts.builder()
                .setIssuer(issuer)
                .setAudience(audience)
                .setSubject(u.getId().toString())
                .claim("typ", "access")
                .claim("role", u.getRole().name())
                .claim("email", u.getEmail())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now.toInstant()))
                .setNotBefore(Date.from(now.toInstant()))
                .setExpiration(Date.from(exp.toInstant()))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
        return new TokenResult(jwt, exp);
    }

    public TokenResult issueRefresh(User u, String issuer, String audience, int ttlDays) {
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime exp = now.plusDays(ttlDays);
        String jwt = Jwts.builder()
                .setIssuer(issuer)
                .setAudience(audience)
                .setSubject(u.getId().toString())
                .claim("typ", "refresh")
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now.toInstant()))
                .setNotBefore(Date.from(now.toInstant()))
                .setExpiration(Date.from(exp.toInstant()))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
        return new TokenResult(jwt, exp);
    }

    public RefreshValidation validateRefresh(String token, String issuer, String audience) {
        try {
            var parser = Jwts.parserBuilder()
                    .requireIssuer(issuer)
                    .requireAudience(audience)
                    .setSigningKey(publicKey)
                    .build();
            Jws<Claims> jws = parser.parseClaimsJws(token);
            Claims c = jws.getBody();
            if (!"refresh".equals(c.get("typ"))) {
                return new RefreshValidation(false, null, "Wrong token type");
            }
            UUID userId = UUID.fromString(c.getSubject());
            return new RefreshValidation(true, userId, null);
        } catch (ExpiredJwtException e) {
            return new RefreshValidation(false, null, "Expired");
        } catch (Exception e) {
            return new RefreshValidation(false, null, "Invalid");
        }
    }
}
