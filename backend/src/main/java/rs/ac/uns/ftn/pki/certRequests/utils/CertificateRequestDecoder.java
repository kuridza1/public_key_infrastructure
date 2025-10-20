package rs.ac.uns.ftn.pki.certRequests.utils;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import rs.ac.uns.ftn.pki.certRequests.dtos.CertificateRequestResponse;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;

public final class CertificateRequestDecoder {

    private CertificateRequestDecoder() {}

    public static CertificateRequestResponse decodeCertificateRequest(CertificateRequest req) {
        try {
            byte[] csrBytes = java.util.Base64.getDecoder().decode(req.getEncodedCsrNoHeader());
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

            // Subject
            X500Name subject = csr.getSubject();
            String cn  = firstRdnValue(subject, BCStyle.CN);
            String o   = firstRdnValue(subject, BCStyle.O);
            String ou  = firstRdnValue(subject, BCStyle.OU);
            String mail= firstRdnValue(subject, BCStyle.EmailAddress);
            String c   = firstRdnValue(subject, BCStyle.C);

            CertificateRequestResponse dto = new CertificateRequestResponse();
            dto.setId(String.valueOf(req.getId()));
            dto.setCommonName(cn == null ? "" : cn);
            dto.setOrganization(o == null ? "" : o);
            dto.setOrganizationalUnit(ou == null ? "" : ou);
            dto.setEmail(mail == null ? "" : mail);
            dto.setCountry(c == null ? "" : c);
            dto.setNotBefore(req.getNotBefore());
            dto.setNotAfter(req.getNotAfter());
            dto.setSubmittedOn(req.getSubmittedOn());

            // Extensions (from extensionRequest attribute)
            Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attrs != null && attrs.length > 0) {
                Extensions exts = Extensions.getInstance(attrs[0].getAttrValues().getObjectAt(0));

                // BasicConstraints
                var bcExt = exts.getExtension(Extension.basicConstraints);
                if (bcExt != null) {
                    BasicConstraints bc = BasicConstraints.getInstance(bcExt.getParsedValue());
                    BasicConstraintsValue value = new BasicConstraintsValue();
                    value.setCa(bc.isCA());
                    if (bc.getPathLenConstraint() != null) {
                        value.setPathLen(bc.getPathLenConstraint().intValue());
                    }
                    dto.setBasicConstraints(value);
                }

                // KeyUsage
                var kuExt = exts.getExtension(Extension.keyUsage);
                if (kuExt != null) {
                    KeyUsage ku = KeyUsage.getInstance(kuExt.getParsedValue());
                    List<KeyUsageValue> list = new ArrayList<>();
                    for (var e : KEY_USAGE_MAP.entrySet()) {
                        if (ku.hasUsages(e.getValue())) {
                            list.add(e.getKey());
                        }
                    }
                    dto.setKeyUsage(list);
                }

                // ExtendedKeyUsage
                var ekuExt = exts.getExtension(Extension.extendedKeyUsage);
                if (ekuExt != null) {
                    ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
                    List<ExtendedKeyUsageValue> list = new ArrayList<>();
                    for (var e : EKU_MAP.entrySet()) {
                        if (eku.hasKeyPurposeId(e.getValue())) {
                            list.add(e.getKey());
                        }
                    }
                    dto.setExtendedKeyUsage(list);
                }

                // SAN
                var sanExt = exts.getExtension(Extension.subjectAlternativeName);
                if (sanExt != null) {
                    GeneralNames san = GeneralNames.getInstance(sanExt.getParsedValue());
                    dto.setSubjectAlternativeNames(ListOfNames.fromGeneralNames(san)); // assumes helper exists
                }

                // IAN
                var ianExt = exts.getExtension(Extension.issuerAlternativeName);
                if (ianExt != null) {
                    GeneralNames ian = GeneralNames.getInstance(ianExt.getParsedValue());
                    dto.setIssuerAlternativeNames(ListOfNames.fromGeneralNames(ian));
                }

                // NameConstraints
                var ncExt = exts.getExtension(Extension.nameConstraints);
                if (ncExt != null) {
                    NameConstraints nc = NameConstraints.getInstance(ncExt.getParsedValue());
                    dto.setNameConstraints(NamesConstraintsValue.fromNameConstraints(nc)); // assumes helper exists
                }

                // CertificatePolicies
                var cpExt = exts.getExtension(Extension.certificatePolicies);
                if (cpExt != null) {
                    CertificatePolicies cps = CertificatePolicies.getInstance(cpExt.getParsedValue());
                    PolicyInformation pi = cps.getPolicyInformation()[0];
                    dto.setCertificatePolicy(CertificatePolicy.fromPolicyInformation(pi)); // assumes helper exists
                }
            }

            return dto;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode CSR", e);
        }
    }

    private static String firstRdnValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0 || rdns[0].getFirst() == null) return null;
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    // --- Maps mirroring your C# dictionaries ---
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
