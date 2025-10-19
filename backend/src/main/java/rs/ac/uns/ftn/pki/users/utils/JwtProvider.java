package rs.ac.uns.ftn.pki.users.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.users.model.User;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtProvider {

    private final PrivateKey privateKey;
    private final Key publicKey; // for validation

    public JwtProvider(
            @Value("${auth.jwt.p12.path}") String p12Path,
            @Value("${auth.jwt.p12.password}") String p12Password,
            @Value("${auth.jwt.p12.alias:jwt}") String alias
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(resolvePath(p12Path))) {
            ks.load(fis, p12Password.toCharArray());
        }
        this.privateKey = (PrivateKey) ks.getKey(alias, p12Password.toCharArray());
        this.publicKey = ks.getCertificate(alias).getPublicKey();
    }

    private static String resolvePath(String p) {
        java.nio.file.Path path = java.nio.file.Paths.get(p);
        if (path.isAbsolute()) return p;
        return java.nio.file.Paths.get(System.getProperty("user.dir"), p).toString();
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
            String sub = c.getSubject();
            UUID userId = UUID.fromString(sub);
            return new RefreshValidation(true, userId, null);
        } catch (ExpiredJwtException e) {
            return new RefreshValidation(false, null, "Expired");
        } catch (Exception e) {
            return new RefreshValidation(false, null, "Invalid");
        }
    }
}
