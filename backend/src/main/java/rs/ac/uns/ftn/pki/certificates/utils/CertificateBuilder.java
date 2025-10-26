package rs.ac.uns.ftn.pki.certificates.utils;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.ExtendedKeyUsageValue;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.KeyUsageValue;
import rs.ac.uns.ftn.pki.certificates.utils.Pkcs12Manager;
import rs.ac.uns.ftn.pki.users.model.User;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;

@Component
public class CertificateBuilder {

    private final Pkcs12Manager pkcs12;

    public CertificateBuilder(Pkcs12Manager pkcs12) {
        this.pkcs12 = pkcs12;
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Main entry: issues self-signed roots and intermediates, saving/reading keys from PKCS#12. */
    public Certificate createCertificate(IssueCertificateRequest request,
                                         AsymmetricKeyParameter subjectPublicKeyParam,
                                         AsymmetricKeyParameter subjectPrivateKeyParam,
                                         Certificate issuerCertificate,
                                         User user) {
        try {
            // ---- Serial (positive 128-bit) ----
            BigInteger serialNumber = new BigInteger(1, uuid16());

            // ---- Names ----
            X500Name subjectName = new X500Name(request.getX509Name().toString());
            X500Name issuerName = issuerCertificate != null
                    ? new X500Name(issuerCertificate.getIssuedTo())
                    : subjectName;

            // ---- Capabilities / pathLen policy ----
            boolean canSign = (request.keyUsage() != null &&
                    request.keyUsage().contains(KeyUsageValue.CertificateSigning)) &&
                    (request.basicConstraints() != null && request.basicConstraints().getIsCa());

            int requestedPathLen = (request.basicConstraints() != null && request.basicConstraints().getPathLen() != null)
                    ? request.basicConstraints().getPathLen() : 0;

            int pathLen;
            if (!canSign) {
                pathLen = -1; // EE
            } else if (issuerCertificate == null) {
                // root: allow requested (or unlimited if not specified)
                pathLen = requestedPathLen;
            } else {
                // intermediate: parent must have remaining depth
                if (issuerCertificate.getPathLen() <= 0) {
                    throw new IllegalStateException("Issuer can't sign CA certificates (pathLen<=0).");
                }
                pathLen = Math.min(requestedPathLen, issuerCertificate.getPathLen() - 1);
            }

            // ---- Validity (avoid LocalDateTime.MAX) ----
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime notBeforeLdt = (request.notBefore() != null)
                    ? request.notBefore()
                    : (issuerCertificate != null ? issuerCertificate.getNotBefore().toLocalDateTime() : now.minusMinutes(1));

            // Simple policy: 10y roots, 5y intermediates, 1y EE (tweak as needed)
            LocalDateTime defaultNotAfter = issuerCertificate == null
                    ? now.plusYears(10)
                    : (canSign ? now.plusYears(5) : now.plusYears(1));

            LocalDateTime notAfterLdt = (request.notAfter() != null)
                    ? request.notAfter()
                    : (issuerCertificate != null ? issuerCertificate.getNotAfter().toLocalDateTime() : defaultNotAfter);

            Date notBefore = toDate(notBeforeLdt);
            Date notAfter  = toDate(notAfterLdt);

            // ---- Subject public key ----
            SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectPublicKeyParam);

            // ---- Builder ----
            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                    issuerName, serialNumber, notBefore, notAfter, subjectName, subjPubKeyInfo
            );

            // ---- Extensions ----
            if (request.basicConstraints() != null) {
                BasicConstraints bcValue = request.basicConstraints().getIsCa()
                        ? new BasicConstraints(request.basicConstraints().getPathLen() != null
                        ? pathLen
                        : Integer.MAX_VALUE) // unlimited if request omitted
                        : new BasicConstraints(false);
                certGen.addExtension(Extension.basicConstraints, true, bcValue);
            } else {
                // Default EE if not provided
                certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            }

            if (request.keyUsage() != null && !request.keyUsage().isEmpty()) {
                int usageBits = 0;
                for (KeyUsageValue ku : request.keyUsage()) {
                    Integer bit = KeyUsageMap.get(ku);
                    if (bit != null) usageBits |= bit;
                }
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(usageBits));
            }

            if (request.extendedKeyUsage() != null && !request.extendedKeyUsage().isEmpty()) {
                List<KeyPurposeId> ekuOids = new ArrayList<>();
                for (ExtendedKeyUsageValue eku : request.extendedKeyUsage()) {
                    KeyPurposeId oid = ExtendedKeyUsageMap.get(eku);
                    if (oid != null) ekuOids.add(oid);
                }
                certGen.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(ekuOids.toArray(new KeyPurposeId[0])));
            }

            if (request.subjectAlternativeNames() != null) {
                GeneralNames san = new GeneralNames(request.subjectAlternativeNames().toGeneralNames());
                certGen.addExtension(Extension.subjectAlternativeName, false, san);
            }

            if (request.issuerAlternativeNames() != null) {
                GeneralNames ian = new GeneralNames(request.issuerAlternativeNames().toGeneralNames());
                certGen.addExtension(Extension.issuerAlternativeName, false, ian);
            }

            if (request.nameConstraints() != null) {
                List<GeneralSubtree> permitted = request.nameConstraints().getPermitted().toGeneralSubtrees();
                List<GeneralSubtree> excluded  = request.nameConstraints().getExcluded().toGeneralSubtrees();
                NameConstraints nameConstraints = new NameConstraints(
                        !permitted.isEmpty() ? permitted.toArray(new GeneralSubtree[0]) : null,
                        !excluded.isEmpty()  ? excluded.toArray(new GeneralSubtree[0])  : null
                );
                certGen.addExtension(Extension.nameConstraints, true, nameConstraints);
            }

            if (request.certificatePolicy() != null) {
                PolicyInformation policyInfo = request.certificatePolicy().toPolicyInformation();
                certGen.addExtension(Extension.certificatePolicies, false, new DERSequence(policyInfo));
            }

            // CRL DP (tweak for your deployment)
            String crlUrl = "https://localhost:8081/api/crl";
            DistributionPointName distPointName = new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)));
            DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
            certGen.addExtension(Extension.cRLDistributionPoints, false, new DERSequence(distPoint));

            // ---- Signer selection ----
            PrivateKey signerPriv;
            if (issuerCertificate != null) {
                if (issuerCertificate.getKeystorePath() == null || issuerCertificate.getKeystoreAlias() == null) {
                    throw new IllegalStateException("Issuer missing keystore reference (path/alias).");
                }
                signerPriv = pkcs12.loadPrivateKey(issuerCertificate.getKeystorePath(),
                        issuerCertificate.getKeystoreAlias());
            } else {
                // self-signed root: convert subject private param to JCA
                PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(subjectPrivateKeyParam);
                signerPriv = new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(pki);
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC")
                    .build(signerPriv);

            var certificateHolder = certGen.build(signer);
            org.bouncycastle.asn1.x509.Certificate certificate = certificateHolder.toASN1Structure();

            // ---- Map to domain object ----
            Certificate result = new Certificate();
            result.setSerialNumber(new java.math.BigInteger(serialNumber.toByteArray()));
            result.setSigningCertificate(issuerCertificate);
            result.setIssuedBy(issuerName.toString());
            result.setIssuedTo(subjectName.toString());
            result.setNotAfter(OffsetDateTime.ofInstant(certificate.getEndDate().getDate().toInstant(), ZoneId.systemDefault()));
            result.setNotBefore(OffsetDateTime.ofInstant(certificate.getStartDate().getDate().toInstant(), ZoneId.systemDefault()));
            result.setEncodedValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            result.setPrivateKey(subjectPrivateKeyParam); // only for immediate return; DO NOT persist
            result.setCanSign(canSign);
            result.setPathLen(pathLen);
            result.setSignedBy(user);

            // ---- Persist the key to PKCS#12 if we own it (roots & any CA keys you generated) ----
            if (issuerCertificate == null) {
                // Save root key+cert to its own PKCS#12 and store reference
                byte[] der = Base64.getDecoder().decode(result.getEncodedValue());
                var rootX509 = Pkcs12Manager.parseX509(der);
                String alias = "ca-" + result.getSerialNumber(); // unique & stable
                var p12 = pkcs12.saveKeyAndChain(alias, signerPriv, new java.security.cert.X509Certificate[]{ rootX509 });
                result.setKeystorePath(p12.getAbsolutePath());
                result.setKeystoreAlias(alias);
            } else if (canSign) {
                // If you also want to save generated intermediate private keys you own (not CSR-based):
                byte[] der = Base64.getDecoder().decode(result.getEncodedValue());
                var childX509 = Pkcs12Manager.parseX509(der);
                String alias = "ca-" + result.getSerialNumber();
                // Optional: include parent in chain for convenience
                java.security.cert.X509Certificate parentX509 =
                        Pkcs12Manager.parseX509(Base64.getDecoder()
                                .decode(issuerCertificate.getEncodedValue()));
                var p12 = pkcs12.saveKeyAndChain(alias, // subject's own private key if you generated it
                        new JcaPEMKeyConverter().setProvider("BC")
                                .getPrivateKey(PrivateKeyInfoFactory.createPrivateKeyInfo(subjectPrivateKeyParam)),
                        new java.security.cert.X509Certificate[]{ childX509, parentX509 });
                result.setKeystorePath(p12.getAbsolutePath());
                result.setKeystoreAlias(alias);
            }
            // For end-entity keys generated by the client (CSR), skip saving private key.

            return result;

        } catch (Exception e) {
            throw new RuntimeException("Failed to create certificate", e);
        }
    }

    // ---- helpers ----
    private static byte[] uuid16() {
        UUID u = UUID.randomUUID();
        byte[] b = new byte[16];
        System.arraycopy(toBytes(u.getMostSignificantBits()), 0, b, 0, 8);
        System.arraycopy(toBytes(u.getLeastSignificantBits()),     0, b, 8, 8);
        return b;
    }
    private static byte[] toBytes(long v) {
        byte[] r = new byte[8];
        for (int i = 7; i >= 0; i--) { r[i] = (byte)(v & 0xFF); v >>= 8; }
        return r;
    }
    private static Date toDate(LocalDateTime ldt) {
        return Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }

    private static final Map<KeyUsageValue, Integer> KeyUsageMap = Map.of(
            KeyUsageValue.DigitalSignature, KeyUsage.digitalSignature,
            KeyUsageValue.NonRepudiation,   KeyUsage.nonRepudiation,
            KeyUsageValue.KeyEncipherment,  KeyUsage.keyEncipherment,
            KeyUsageValue.DataEncipherment, KeyUsage.dataEncipherment,
            KeyUsageValue.KeyAgreement,     KeyUsage.keyAgreement,
            KeyUsageValue.CertificateSigning, KeyUsage.keyCertSign,
            KeyUsageValue.CrlSigning,       KeyUsage.cRLSign,
            KeyUsageValue.EncipherOnly,     KeyUsage.encipherOnly,
            KeyUsageValue.DecipherOnly,     KeyUsage.decipherOnly
    );

    private static final Map<ExtendedKeyUsageValue, KeyPurposeId> ExtendedKeyUsageMap = Map.of(
            ExtendedKeyUsageValue.ServerAuthentication, KeyPurposeId.id_kp_serverAuth,
            ExtendedKeyUsageValue.ClientAuthentication, KeyPurposeId.id_kp_clientAuth,
            ExtendedKeyUsageValue.CodeSigning,          KeyPurposeId.id_kp_codeSigning,
            ExtendedKeyUsageValue.EmailProtection,      KeyPurposeId.id_kp_emailProtection,
            ExtendedKeyUsageValue.IpSecEndSystem,       KeyPurposeId.id_kp_ipsecEndSystem,
            ExtendedKeyUsageValue.IpSecTunnel,          KeyPurposeId.id_kp_ipsecTunnel,
            ExtendedKeyUsageValue.IpSecUser,            KeyPurposeId.id_kp_ipsecUser,
            ExtendedKeyUsageValue.TimeStamping,         KeyPurposeId.id_kp_timeStamping,
            ExtendedKeyUsageValue.OcspSigning,          KeyPurposeId.id_kp_OCSPSigning,
            ExtendedKeyUsageValue.Dvcs,                 KeyPurposeId.id_kp_dvcs
    );
}
