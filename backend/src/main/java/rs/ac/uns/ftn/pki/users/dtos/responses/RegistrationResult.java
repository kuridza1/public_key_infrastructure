package rs.ac.uns.ftn.pki.users.dtos.responses;

public class RegistrationResult {
    private boolean ok;
    private int statusCode;
    private RegisterResponse response;

    public RegistrationResult() {}

    public RegistrationResult(boolean ok, int statusCode, RegisterResponse response) {
        this.ok = ok;
        this.statusCode = statusCode;
        this.response = response;
    }

    public boolean isOk() { return ok; }
    public void setOk(boolean ok) { this.ok = ok; }

    public int getStatusCode() { return statusCode; }
    public void setStatusCode(int statusCode) { this.statusCode = statusCode; }

    public RegisterResponse getResponse() { return response; }
    public void setResponse(RegisterResponse response) { this.response = response; }
}
