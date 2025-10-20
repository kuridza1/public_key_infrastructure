package rs.ac.uns.ftn.pki.certRequests.utils;

import java.security.KeyPair;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import rs.ac.uns.ftn.pki.certRequests.dtos.CreateCertificateRequestDTO;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;
import rs.ac.uns.ftn.pki.users.model.User;


public final class CertificateRequestBuilder {

    private CertificateRequestBuilder() {}

    /**
     * Build a PKCS#10 CSR with requested extensions and return a CertificateRequest entity.
     */
    public static CertificateRequest createCertificateRequest(
            CreateCertificateRequestDTO request,
            KeyPair keyPair,
            User requestedFrom,
            User requestedFor
    ) {
        try {
            // Subject from DTO (DTO returns X509Name; convert to X500Name)
            X500Name subject = new X500Name(request.getX509Name().toString());

            // ----- Extensions -----
            ExtensionsGenerator extGen = new ExtensionsGenerator();

            // BasicConstraints
            BasicConstraintsValue bcVal = request.getBasicConstraints();
            if (bcVal != null) {
                BasicConstraints bc = bcVal.isCa()
                        ? new BasicConstraints(bcVal.getPathLen() == null ? 0 : bcVal.getPathLen())
                        : new BasicConstraints(false);
                extGen.addExtension(Extension.basicConstraints, true, bc);
            }

            // KeyUsage (bitmask)
            if (request.getKeyUsage() != null && !request.getKeyUsage().isEmpty()) {
                int usageBits = 0;
                for (KeyUsageValue ku : request.getKeyUsage()) {
                    Integer bit = KEY_USAGE_MAP.get(ku);
                    if (bit != null) usageBits |= bit;
                }
                extGen.addExtension(Extension.keyUsage, true, new KeyUsage(usageBits));
            }

            // ExtendedKeyUsage (sequence of OIDs)
            if (request.getExtendedKeyUsage() != null && !request.getExtendedKeyUsage().isEmpty()) {
                List<KeyPurposeId> oids = new ArrayList<>();
                for (ExtendedKeyUsageValue eku : request.getExtendedKeyUsage()) {
                    KeyPurposeId oid = EKU_MAP.get(eku);
                    if (oid != null) oids.add(oid);
                }
                if (!oids.isEmpty()) {
                    extGen.addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(oids.toArray(KeyPurposeId[]::new)));
                }
            }

            // Subject Alternative Names
            if (request.getSubjectAlternativeNames != null) {
                ListOfNames sanList = request.getSubjectAlternativeNames();
                GeneralNames san = sanList.toGeneralNames(); // assumes your domain class has this
                extGen.addExtension(Extension.subjectAlternativeName, false, san);
            }

            // Issuer Alternative Names
            if (request.getIssuerAlternativeNames() != null) {
                ListOfNames ianList = request.getIssuerAlternativeNames();
                GeneralNames ian = ianList.toGeneralNames();
                extGen.addExtension(Extension.issuerAlternativeName, false, ian);
            }

            // Name Constraints
            if (request.getNameConstraints() != null) {
                NamesConstraintsValue ncv = request.getNameConstraints();
                var permitted = ncv.getPermitted().toGeneralSubtrees();
                var excluded  = ncv.getExcluded().toGeneralSubtrees();
                NameConstraints nc = new NameConstraints(
                        permitted == null || permitted.size() == 0 ? null : permitted,
                        excluded  == null || excluded.size()  == 0 ? null : excluded
                );
                extGen.addExtension(Extension.nameConstraints, true, nc);
            }

            // Certificate Policies
            if (request.getCertificatePolicy() != null) {
                CertificatePolicy cp = request.getCertificatePolicy();
                PolicyInformation pi = cp.toPolicyInformation(); // assumes your domain class has this
                extGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(pi));
            }

            Extensions extensions = extGen.generate();

            // ----- CSR builder with extensionRequest attribute -----
            PKCS10CertificationRequestBuilder csrBuilder =
                    new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

            Attribute extReqAttr = new Attribute(
                    PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    new DERSet(extensions)
            );
            csrBuilder.addAttribute(extReqAttr.getAttrType(), extReqAttr.getAttrValues());

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            // ----- Persistable entity -----
            CertificateRequest entity = new CertificateRequest();
            entity.setEncodedCSR(java.util.Base64.getEncoder().encodeToString(csr.getEncoded()));
            entity.setRequestedFor(requestedFor);
            entity.setRequestedFrom(requestedFrom);
            entity.setNotBefore(request.getNotBefore());
            entity.setNotAfter(request.getNotAfter());
            entity.setSubmittedOn(LocalDateTime.now()); // or UTC via Clock if you prefer

            return entity;
        } catch (Exception e) {
            throw new RuntimeException("Failed to build CSR", e);
        }
    }

    // --- Maps (KeyUsage / EKU) ---
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
