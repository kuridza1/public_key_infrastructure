package rs.ac.uns.ftn.pki.users.dtos.responses;

import java.time.OffsetDateTime;

public class RefreshResponse {

    private String accessToken;
    private OffsetDateTime accessExpiresAt;
    private String refreshToken;
    private OffsetDateTime refreshExpiresAt;
    private String userId;

    public RefreshResponse() {
    }

    public RefreshResponse(String accessToken, OffsetDateTime accessExpiresAt,
                           String refreshToken, OffsetDateTime refreshExpiresAt,
                           String userId) {
        this.accessToken = accessToken;
        this.accessExpiresAt = accessExpiresAt;
        this.refreshToken = refreshToken;
        this.refreshExpiresAt = refreshExpiresAt;
        this.userId = userId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public OffsetDateTime getAccessExpiresAt() {
        return accessExpiresAt;
    }

    public void setAccessExpiresAt(OffsetDateTime accessExpiresAt) {
        this.accessExpiresAt = accessExpiresAt;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public OffsetDateTime getRefreshExpiresAt() {
        return refreshExpiresAt;
    }

    public void setRefreshExpiresAt(OffsetDateTime refreshExpiresAt) {
        this.refreshExpiresAt = refreshExpiresAt;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
