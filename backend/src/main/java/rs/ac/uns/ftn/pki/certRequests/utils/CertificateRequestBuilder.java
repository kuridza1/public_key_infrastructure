package rs.ac.uns.ftn.pki.certRequests.utils;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import rs.ac.uns.ftn.pki.certRequests.dtos.CreateCertificateRequestDTO;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;
import rs.ac.uns.ftn.pki.users.model.User;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.*;

public final class CertificateRequestBuilder {

    private CertificateRequestBuilder() {}

    public static CertificateRequest createCertificateRequest(
            CreateCertificateRequestDTO request,
            KeyPair keyPair,
            User requestedFrom,
            User requestedFor
    ) {
        try {
            X500Name subject = new X500Name(request.getX500Name().toString());

            // ----- Extensions (guarded) -----
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            int extCount = 0;

            // BasicConstraints
            BasicConstraintsValue bcVal = request.getBasicConstraints();
            if (bcVal != null) {
                BasicConstraints bc = bcVal.getIsCa()
                        ? new BasicConstraints(bcVal.getPathLen() == null ? 0 : bcVal.getPathLen())
                        : new BasicConstraints(false);
                extGen.addExtension(Extension.basicConstraints, true, bc);
                extCount++;
            }

            // KeyUsage
            if (request.getKeyUsage() != null && !request.getKeyUsage().isEmpty()) {
                int usageBits = 0;
                for (KeyUsageValue ku : request.getKeyUsage()) {
                    Integer bit = KEY_USAGE_MAP.get(ku);
                    if (bit != null) usageBits |= bit;
                }
                if (usageBits != 0) {
                    extGen.addExtension(Extension.keyUsage, true, new KeyUsage(usageBits));
                    extCount++;
                }
            }

            // ExtendedKeyUsage
            if (request.getExtendedKeyUsage() != null && !request.getExtendedKeyUsage().isEmpty()) {
                List<KeyPurposeId> oids = new ArrayList<>();
                for (ExtendedKeyUsageValue eku : request.getExtendedKeyUsage()) {
                    KeyPurposeId oid = EKU_MAP.get(eku);
                    if (oid != null) oids.add(oid);
                }
                if (!oids.isEmpty()) {
                    extGen.addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(oids.toArray(KeyPurposeId[]::new)));
                    extCount++;
                }
            }

            // Subject Alternative Names
            if (request.getSubjectAlternativeNames() != null) {
                var sanArray = request.getSubjectAlternativeNames().toGeneralNames();
                if (sanArray != null && sanArray.length > 0) {
                    extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sanArray));
                    extCount++;
                }
            }

            // Issuer Alternative Names
            if (request.getIssuerAlternativeNames() != null) {
                var ianArray = request.getIssuerAlternativeNames().toGeneralNames();
                if (ianArray != null && ianArray.length > 0) {
                    extGen.addExtension(Extension.issuerAlternativeName, false, new GeneralNames(ianArray));
                    extCount++;
                }
            }

            // Name Constraints
            if (request.getNameConstraints() != null) {
                var permitted = request.getNameConstraints().getPermitted().toGeneralSubtrees();
                var excluded  = request.getNameConstraints().getExcluded().toGeneralSubtrees();

                GeneralSubtree[] permArr = (permitted != null && !permitted.isEmpty())
                        ? permitted.toArray(new GeneralSubtree[0]) : null;
                GeneralSubtree[] exclArr = (excluded  != null && !excluded.isEmpty())
                        ? excluded.toArray(new GeneralSubtree[0])  : null;

                if (permArr != null || exclArr != null) {
                    extGen.addExtension(Extension.nameConstraints, true, new NameConstraints(permArr, exclArr));
                    extCount++;
                }
            }

            // Certificate Policies
            if (request.getCertificatePolicy() != null) {
                PolicyInformation pi = request.getCertificatePolicy().toPolicyInformation();
                if (pi != null) {
                    extGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(pi));
                    extCount++;
                }
            }

            // ----- CSR builder -----
            PKCS10CertificationRequestBuilder csrBuilder =
                    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            // attach extensionRequest attribute only if we added something
            if (extCount > 0) {
                Extensions exts = extGen.generate();
                Attribute extReqAttr = new Attribute(
                        PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        new DERSet(exts)
                );
                csrBuilder.addAttribute(extReqAttr.getAttrType(), extReqAttr.getAttrValues());
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // ----- Persistable entity -----
            CertificateRequest entity = new CertificateRequest();
            entity.setEncodedCSR(Base64.getEncoder().encodeToString(csr.getEncoded())); // raw DER -> Base64 (no PEM)
            entity.setRequestedFor(requestedFor);
            entity.setRequestedFrom(requestedFrom);
            entity.setNotBefore(request.getNotBefore());
            entity.setNotAfter(request.getNotAfter());
            entity.setSubmittedOn(LocalDateTime.now());

            return entity;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build CSR", e);
        }
    }

    // --- Maps ---
    private static final Map<KeyUsageValue, Integer> KEY_USAGE_MAP = new EnumMap<>(KeyUsageValue.class);
    private static final Map<ExtendedKeyUsageValue, KeyPurposeId> EKU_MAP = new EnumMap<>(ExtendedKeyUsageValue.class);
    static {
        KEY_USAGE_MAP.put(KeyUsageValue.DigitalSignature,  KeyUsage.digitalSignature);
        KEY_USAGE_MAP.put(KeyUsageValue.NonRepudiation,    KeyUsage.nonRepudiation);
        KEY_USAGE_MAP.put(KeyUsageValue.KeyEncipherment,   KeyUsage.keyEncipherment);
        KEY_USAGE_MAP.put(KeyUsageValue.DataEncipherment,  KeyUsage.dataEncipherment);
        KEY_USAGE_MAP.put(KeyUsageValue.KeyAgreement,      KeyUsage.keyAgreement);
        KEY_USAGE_MAP.put(KeyUsageValue.CertificateSigning,KeyUsage.keyCertSign);
        KEY_USAGE_MAP.put(KeyUsageValue.CrlSigning,        KeyUsage.cRLSign);
        KEY_USAGE_MAP.put(KeyUsageValue.EncipherOnly,      KeyUsage.encipherOnly);
        KEY_USAGE_MAP.put(KeyUsageValue.DecipherOnly,      KeyUsage.decipherOnly);

        EKU_MAP.put(ExtendedKeyUsageValue.ServerAuthentication,  KeyPurposeId.id_kp_serverAuth);
        EKU_MAP.put(ExtendedKeyUsageValue.ClientAuthentication,  KeyPurposeId.id_kp_clientAuth);
        EKU_MAP.put(ExtendedKeyUsageValue.CodeSigning,           KeyPurposeId.id_kp_codeSigning);
        EKU_MAP.put(ExtendedKeyUsageValue.EmailProtection,       KeyPurposeId.id_kp_emailProtection);
        EKU_MAP.put(ExtendedKeyUsageValue.IpSecEndSystem,        KeyPurposeId.id_kp_ipsecEndSystem);
        EKU_MAP.put(ExtendedKeyUsageValue.IpSecTunnel,           KeyPurposeId.id_kp_ipsecTunnel);
        EKU_MAP.put(ExtendedKeyUsageValue.IpSecUser,             KeyPurposeId.id_kp_ipsecUser);
        EKU_MAP.put(ExtendedKeyUsageValue.TimeStamping,          KeyPurposeId.id_kp_timeStamping);
        EKU_MAP.put(ExtendedKeyUsageValue.OcspSigning,           KeyPurposeId.id_kp_OCSPSigning);
        EKU_MAP.put(ExtendedKeyUsageValue.Dvcs,                  KeyPurposeId.id_kp_dvcs);
    }
}
