package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;

import java.util.Objects;

public class CertificatePolicy {
    private String policyIdentifier;
    private String cpsUri;
    private String userNotice;

    // Constructors
    public CertificatePolicy() {}

    public CertificatePolicy(String policyIdentifier, String cpsUri, String userNotice) {
        this.policyIdentifier = policyIdentifier;
        this.cpsUri = cpsUri;
        this.userNotice = userNotice;
    }

    // Getters and Setters
    public String getPolicyIdentifier() {
        return policyIdentifier;
    }

    public void setPolicyIdentifier(String policyIdentifier) {
        this.policyIdentifier = policyIdentifier;
    }

    public String getCpsUri() {
        return cpsUri;
    }

    public void setCpsUri(String cpsUri) {
        this.cpsUri = cpsUri;
    }

    public String getUserNotice() {
        return userNotice;
    }

    public void setUserNotice(String userNotice) {
        this.userNotice = userNotice;
    }

    public PolicyInformation toPolicyInformation() {
        ASN1ObjectIdentifier policyId = new ASN1ObjectIdentifier(policyIdentifier);
        ASN1EncodableVector qualifiers = new ASN1EncodableVector();

        if (cpsUri != null && !cpsUri.isEmpty()) {
            ASN1EncodableVector cpsSeq = new ASN1EncodableVector();
            cpsSeq.add(PolicyQualifierId.id_qt_cps);
            cpsSeq.add(new DERIA5String(cpsUri));
            qualifiers.add(new DERSequence(cpsSeq));
        }

        if (userNotice != null && !userNotice.isEmpty()) {
            ASN1EncodableVector noticeSeq = new ASN1EncodableVector();
            noticeSeq.add(PolicyQualifierId.id_qt_unotice);
            noticeSeq.add(new DERUTF8String(userNotice));
            qualifiers.add(new DERSequence(noticeSeq));
        }

        return qualifiers.size() > 0
                ? new PolicyInformation(policyId, new DERSequence(qualifiers))
                : new PolicyInformation(policyId);
    }

    public static CertificatePolicy fromPolicyInformation(PolicyInformation policyInfo) {
        CertificatePolicy cp = new CertificatePolicy();
        cp.setPolicyIdentifier(policyInfo.getPolicyIdentifier().getId());
        cp.setCpsUri("");
        cp.setUserNotice("");

        if (policyInfo.getPolicyQualifiers() != null) {
            ASN1Sequence qualifiers = policyInfo.getPolicyQualifiers();
            for (int i = 0; i < qualifiers.size(); i++) {
                ASN1Sequence seq = ASN1Sequence.getInstance(qualifiers.getObjectAt(i));
                ASN1ObjectIdentifier qualifierId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

                if (qualifierId.equals(PolicyQualifierId.id_qt_cps) && seq.size() > 1) {
                    ASN1IA5String ia5String = ASN1IA5String.getInstance(seq.getObjectAt(1));
                    cp.setCpsUri(ia5String.getString());
                }

                if (qualifierId.equals(PolicyQualifierId.id_qt_unotice) && seq.size() > 1) {
                    ASN1UTF8String utf8String = ASN1UTF8String.getInstance(seq.getObjectAt(1));
                    cp.setUserNotice(utf8String.getString());
                }
            }
        }

        return cp;
    }

    // Optional: Override toString, equals, and hashCode
    @Override
    public String toString() {
        return "CertificatePolicy{" +
                "policyIdentifier='" + policyIdentifier + '\'' +
                ", cpsUri='" + cpsUri + '\'' +
                ", userNotice='" + userNotice + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CertificatePolicy that = (CertificatePolicy) o;
        return Objects.equals(policyIdentifier, that.policyIdentifier) &&
                Objects.equals(cpsUri, that.cpsUri) &&
                Objects.equals(userNotice, that.userNotice);
    }

    @Override
    public int hashCode() {
        return Objects.hash(policyIdentifier, cpsUri, userNotice);
    }
}