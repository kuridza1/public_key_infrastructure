package rs.ac.uns.ftn.pki.crl.model;

public enum RevocationReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    AFFILIATION_CHANGED(2),
    SUPERSEDED(3),
    CESSATION_OF_OPERATION(4),
    PRIVILEGE_WITHDRAWN(5);

    private final int code;

    RevocationReason(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static RevocationReason fromCode(int code) {
        for (RevocationReason reason : values()) {
            if (reason.code == code) {
                return reason;
            }
        }
        throw new IllegalArgumentException("Invalid RevocationReason code: " + code);
    }
}
