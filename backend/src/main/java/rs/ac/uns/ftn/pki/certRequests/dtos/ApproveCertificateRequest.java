package rs.ac.uns.ftn.pki.certRequests.dtos;


public class ApproveCertificateRequest {

    private String requestId;
    private IssueCertificateRequest requestForm;

    public ApproveCertificateRequest() {}

    public ApproveCertificateRequest(String requestId, IssueCertificateRequest requestForm) {
        this.requestId = requestId;
        this.requestForm = requestForm;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public IssueCertificateRequest getRequestForm() {
        return requestForm;
    }

    public void setRequestForm(IssueCertificateRequest requestForm) {
        this.requestForm = requestForm;
    }
}
