package rs.ac.uns.ftn.pki.certRequests.utils;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import rs.ac.uns.ftn.pki.certRequests.dtos.CertificateRequestResponse;
import rs.ac.uns.ftn.pki.certRequests.model.CertificateRequest;
import rs.ac.uns.ftn.pki.certificates.model.extensionValues.*;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;

public final class CertificateRequestDecoder {

    private CertificateRequestDecoder() {}

    public static CertificateRequestResponse decodeCertificateRequest(CertificateRequest req) {
        try {
            // 1) Load raw string from DB (support either normalized or original)
            String raw = nullSafe(req.getEncodedCsrNormalized());
            if (raw.isBlank()) raw = nullSafe(req.getEncodedCSR());
            if (raw.isBlank()) throw new IllegalArgumentException("Empty CSR");

            // 2) Normalize & decode to DER
            byte[] der = readCsrDerBytes(raw);

            // 3) Quick DER sanity: must start with SEQUENCE (0x30)
            if (der.length < 2 || (der[0] & 0xFF) != 0x30) {
                throw new IllegalArgumentException("CSR is not DER SEQUENCE (first byte = " +
                        (der.length == 0 ? "<empty>" : String.format("0x%02X", der[0])) + ")");
            }

            // 4) Build PKCS#10 object
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);

            // 5) Subject DN
            X500Name subject = csr.getSubject();
            String cn   = firstRdnValue(subject, BCStyle.CN);
            String o    = firstRdnValue(subject, BCStyle.O);
            String ou   = firstRdnValue(subject, BCStyle.OU);
            String mail = firstRdnValue(subject, BCStyle.EmailAddress);
            String c    = firstRdnValue(subject, BCStyle.C);

            CertificateRequestResponse dto = new CertificateRequestResponse();
            dto.setId(String.valueOf(req.getId()));
            dto.setCommonName(orEmpty(cn));
            dto.setOrganization(orEmpty(o));
            dto.setOrganizationalUnit(orEmpty(ou));
            dto.setEmail(orEmpty(mail));
            dto.setCountry(orEmpty(c));
            dto.setNotBefore(req.getNotBefore());
            dto.setNotAfter(req.getNotAfter());
            dto.setSubmittedOn(req.getSubmittedOn());

            // 6) Extensions (pkcs-9-at-extensionRequest)
            Attribute[] attrs = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            if (attrs != null && attrs.length > 0) {
                // Per our builder, the attribute value is a SET containing a single "Extensions"
                ASN1Encodable val0 = attrs[0].getAttrValues().getObjectAt(0);
                Extensions exts = Extensions.getInstance(val0);

                // BasicConstraints
                var bcExt = exts.getExtension(Extension.basicConstraints);
                if (bcExt != null) {
                    BasicConstraints bc = BasicConstraints.getInstance(bcExt.getParsedValue());
                    var value = new BasicConstraintsValue();
                    value.setIsCa(bc.isCA());
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
                        if (ku.hasUsages(e.getValue())) list.add(e.getKey());
                    }
                    dto.setKeyUsage(list);
                }

                // ExtendedKeyUsage
                var ekuExt = exts.getExtension(Extension.extendedKeyUsage);
                if (ekuExt != null) {
                    ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuExt.getParsedValue());
                    List<ExtendedKeyUsageValue> list = new ArrayList<>();
                    for (var e : EKU_MAP.entrySet()) {
                        if (eku.hasKeyPurposeId(e.getValue())) list.add(e.getKey());
                    }
                    dto.setExtendedKeyUsage(list);
                }

                // SAN
                var sanExt = exts.getExtension(Extension.subjectAlternativeName);
                if (sanExt != null) {
                    GeneralNames san = GeneralNames.getInstance(sanExt.getParsedValue());
                    dto.setSubjectAlternativeNames(ListOfNames.fromGeneralNames(san));
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
                    dto.setNameConstraints(NamesConstraintsValue.fromNameConstraints(nc));
                }

                // CertificatePolicies
                var cpExt = exts.getExtension(Extension.certificatePolicies);
                if (cpExt != null) {
                    CertificatePolicies cps = CertificatePolicies.getInstance(cpExt.getParsedValue());
                    PolicyInformation[] pis = cps.getPolicyInformation();
                    if (pis != null && pis.length > 0) {
                        dto.setCertificatePolicy(CertificatePolicy.fromPolicyInformation(pis[0]));
                    }
                }
            }

            return dto;

        } catch (Exception e) {
            throw new RuntimeException("Failed to decode CSR", e);
        }
    }

    // -------- robust input handling --------

    private static byte[] readCsrDerBytes(String raw) {
        String s = raw.trim();

        // Case A: PEM
        if (s.contains("-----BEGIN CERTIFICATE REQUEST-----")) {
            String inner = s
                    .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                    .replace("-----END CERTIFICATE REQUEST-----", "")
                    .replaceAll("\\s+", "");
            return base64ToDer(inner);
        }

        // Case B: raw Base64(DER) OR Base64(Base64(DER)) (double-encoded)
        // First attempt: assume single Base64 of DER
        byte[] first = tryBase64(s);
        if (looksLikeDer(first)) return first;

        // If not DER, maybe the decoded bytes are text that contain Base64 again (double-Base64)
        // Try to interpret first decode as UTF-8 text with Base64 inside (strip whitespace)
        String innerCandidate = new String(first, StandardCharsets.UTF_8).replaceAll("\\s+", "");
        byte[] second = tryBase64(innerCandidate);
        if (looksLikeDer(second)) return second;

        // One more fallback: if raw had whitespace/newlines, strip and try again
        String compact = s.replaceAll("\\s+", "");
        byte[] again = tryBase64(compact);
        if (looksLikeDer(again)) return again;

        // Give up with a clear message
        throw new IllegalArgumentException("CSR content is not PEM, not single Base64(DER), " +
                "and not double-Base64(DER).");
    }

    private static byte[] base64ToDer(String base64) {
        byte[] bytes = tryBase64(base64);
        if (!looksLikeDer(bytes)) {
            throw new IllegalArgumentException("Decoded PEM body is not DER (does not start with 0x30).");
        }
        return bytes;
    }

    private static byte[] tryBase64(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            // Return empty; caller will decide next step
            return new byte[0];
        }
    }

    private static boolean looksLikeDer(byte[] bytes) {
        return bytes != null && bytes.length > 2 && (bytes[0] & 0xFF) == 0x30;
    }

    // -------- small helpers --------

    private static String nullSafe(String v) { return v == null ? "" : v; }

    private static String firstRdnValue(X500Name name, ASN1ObjectIdentifier oid) {
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0 || rdns[0].getFirst() == null) return null;
        return IETFUtils.valueToString(rdns[0].getFirst().getValue());
    }

    private static String orEmpty(String s) { return s == null ? "" : s; }

    // Maps
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
