package rs.ac.uns.ftn.pki.certificates.utils;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;
import rs.ac.uns.ftn.pki.certificates.dtos.IssueCertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.ExtendedKeyUsageValue;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.KeyUsageValue;
import rs.ac.uns.ftn.pki.users.model.User;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;

@Component
public class CertificateBuilder {

    public static Certificate createCertificate(IssueCertificateRequest request,
                                                AsymmetricKeyParameter subjectPublicKeyParam,
                                                AsymmetricKeyParameter subjectPrivateKeyParam,
                                                Certificate issuerCertificate,
                                                User user) {
        try {
            // serial number from UUID
            UUID uuid = UUID.randomUUID();
            byte[] guidBytes = new byte[16];
            System.arraycopy(toBytes(uuid.getMostSignificantBits()), 0, guidBytes, 0, 8);
            System.arraycopy(toBytes(uuid.getLeastSignificantBits()), 0, guidBytes, 8, 8);
            BigInteger serialNumber = new BigInteger(1, guidBytes);

            // Convert names to X500Name
            X500Name subjectName = new X500Name(request.getX509Name().toString());
            X500Name issuerName = issuerCertificate != null ?
                    new X500Name(issuerCertificate.getIssuedTo()) :
                    subjectName;

            boolean canSign = (request.keyUsage() != null &&
                    request.keyUsage().contains(KeyUsageValue.CertificateSigning)) &&
                    (request.basicConstraints() != null && request.basicConstraints().getIsCa());

            int pathLen = !canSign ? -1 :
                    (request.basicConstraints() != null && request.basicConstraints().getPathLen() != null ?
                            request.basicConstraints().getPathLen() : 0);

            if (canSign && issuerCertificate != null && issuerCertificate.getPathLen() <= 0) {
                throw new Exception("Issuing certificate can't be used for signing CA certificates!");
            }

            // Prepare SubjectPublicKeyInfo
            SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(subjectPublicKeyParam);

            // Build X509v3CertificateBuilder
            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                    issuerName,
                    serialNumber,
                    toDate(request.notBefore() != null ? request.notBefore() :
                            (issuerCertificate != null ? issuerCertificate.getNotBefore().toLocalDateTime() : LocalDateTime.now())),
                    toDate(request.notAfter() != null ? request.notAfter() :
                            (issuerCertificate != null ? issuerCertificate.getNotAfter().toLocalDateTime() : LocalDateTime.MAX)),
                    subjectName,
                    subjPubKeyInfo
            );

            // Add extensions directly
            if (request.basicConstraints() != null) {
                BasicConstraints bcValue = request.basicConstraints().getIsCa() ?
                        new BasicConstraints(request.basicConstraints().getPathLen() != null ?
                                request.basicConstraints().getPathLen() : Integer.MAX_VALUE) :
                        new BasicConstraints(false);
                certGen.addExtension(Extension.basicConstraints, true, bcValue);
            }

            if (request.keyUsage() != null && !request.keyUsage().isEmpty()) {
                int usageBits = 0;
                for (KeyUsageValue ku : request.keyUsage()) {
                    if (KeyUsageMap.containsKey(ku)) {
                        usageBits |= KeyUsageMap.get(ku);
                    }
                }
                certGen.addExtension(Extension.keyUsage, true, new KeyUsage(usageBits));
            }

            if (request.extendedKeyUsage() != null && !request.extendedKeyUsage().isEmpty()) {
                List<KeyPurposeId> ekuOids = new ArrayList<>();
                for (ExtendedKeyUsageValue eku : request.extendedKeyUsage()) {
                    if (ExtendedKeyUsageMap.containsKey(eku)) {
                        ekuOids.add(ExtendedKeyUsageMap.get(eku));
                    }
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
                List<GeneralSubtree> excluded = request.nameConstraints().getExcluded().toGeneralSubtrees();
                NameConstraints nameConstraints = new NameConstraints(
                        !permitted.isEmpty() ? permitted.toArray(new GeneralSubtree[0]) : null,
                        !excluded.isEmpty() ? excluded.toArray(new GeneralSubtree[0]) : null
                );
                certGen.addExtension(Extension.nameConstraints, true, nameConstraints);
            }

            if (request.certificatePolicy() != null) {
                PolicyInformation policyInfo = request.certificatePolicy().toPolicyInformation();
                certGen.addExtension(Extension.certificatePolicies, false, new DERSequence(policyInfo));
            }

            // CRL distribution point
            String crlUrl = "https://localhost:8081/api/crl";
            DistributionPointName distPointName = new DistributionPointName(
                    new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)));
            DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
            certGen.addExtension(Extension.cRLDistributionPoints, false, new DERSequence(distPoint));

            // Determine signing key (use issuer's private key if present, otherwise subjectPrivateKeyParam)
            AsymmetricKeyParameter signerKeyParam = issuerCertificate != null ?
                    issuerCertificate.getPrivateKey() : subjectPrivateKeyParam;

            // Convert signerKeyParam -> PrivateKey (JCA) for JcaContentSignerBuilder
            PrivateKeyInfo signerPrivInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(signerKeyParam);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKey signerPriv = converter.getPrivateKey(signerPrivInfo);

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerPriv);

            var certificateHolder = certGen.build(signer);
            org.bouncycastle.asn1.x509.Certificate certificate = certificateHolder.toASN1Structure();

            // Convert to domain Certificate
            Certificate result = new Certificate();
            result.setSerialNumber(new java.math.BigInteger(serialNumber.toByteArray()));
            result.setSigningCertificate(issuerCertificate);
            result.setIssuedBy(issuerName.toString());
            result.setIssuedTo(subjectName.toString());

            // Convert ASN1 Dates to OffsetDateTime
            result.setNotAfter(OffsetDateTime.ofInstant(certificate.getEndDate().getDate().toInstant(), ZoneId.systemDefault()));
            result.setNotBefore(OffsetDateTime.ofInstant(certificate.getStartDate().getDate().toInstant(), ZoneId.systemDefault()));

            result.setEncodedValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
            result.setPrivateKey(subjectPrivateKeyParam);
            result.setCanSign(canSign);
            result.setPathLen(pathLen);
            result.setSignedBy(user);

            return result;

        } catch (Exception e) {
            throw new RuntimeException("Failed to create certificate", e);
        }
    }

    private static byte[] toBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 7; i >= 0; i--) {
            result[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return result;
    }

    private static Date toDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    private static final Map<KeyUsageValue, Integer> KeyUsageMap = Map.of(
            KeyUsageValue.DigitalSignature, KeyUsage.digitalSignature,
            KeyUsageValue.NonRepudiation, KeyUsage.nonRepudiation,
            KeyUsageValue.KeyEncipherment, KeyUsage.keyEncipherment,
            KeyUsageValue.DataEncipherment, KeyUsage.dataEncipherment,
            KeyUsageValue.KeyAgreement, KeyUsage.keyAgreement,
            KeyUsageValue.CertificateSigning, KeyUsage.keyCertSign,
            KeyUsageValue.CrlSigning, KeyUsage.cRLSign,
            KeyUsageValue.EncipherOnly, KeyUsage.encipherOnly,
            KeyUsageValue.DecipherOnly, KeyUsage.decipherOnly
    );

    private static final Map<ExtendedKeyUsageValue, KeyPurposeId> ExtendedKeyUsageMap = Map.of(
            ExtendedKeyUsageValue.ServerAuthentication, KeyPurposeId.id_kp_serverAuth,
            ExtendedKeyUsageValue.ClientAuthentication, KeyPurposeId.id_kp_clientAuth,
            ExtendedKeyUsageValue.CodeSigning, KeyPurposeId.id_kp_codeSigning,
            ExtendedKeyUsageValue.EmailProtection, KeyPurposeId.id_kp_emailProtection,
            ExtendedKeyUsageValue.IpSecEndSystem, KeyPurposeId.id_kp_ipsecEndSystem,
            ExtendedKeyUsageValue.IpSecTunnel, KeyPurposeId.id_kp_ipsecTunnel,
            ExtendedKeyUsageValue.IpSecUser, KeyPurposeId.id_kp_ipsecUser,
            ExtendedKeyUsageValue.TimeStamping, KeyPurposeId.id_kp_timeStamping,
            ExtendedKeyUsageValue.OcspSigning, KeyPurposeId.id_kp_OCSPSigning,
            ExtendedKeyUsageValue.Dvcs, KeyPurposeId.id_kp_dvcs
    );
}
