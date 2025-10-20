package rs.ac.uns.ftn.pki.users.dtos.responses;

import java.time.OffsetDateTime;

public class LoginResponse {

    private String accessToken;
    private OffsetDateTime accessExpiresAt;
    private String refreshToken;
    private OffsetDateTime refreshExpiresAt;
    private String userId;
    private String role;
    private String name;
    private String surname;

    public LoginResponse() {
    }

    public LoginResponse(String accessToken,
                         OffsetDateTime accessExpiresAt,
                         String refreshToken,
                         OffsetDateTime refreshExpiresAt,
                         String userId,
                         String role,
                         String name,
                         String surname) {
        this.accessToken = accessToken;
        this.accessExpiresAt = accessExpiresAt;
        this.refreshToken = refreshToken;
        this.refreshExpiresAt = refreshExpiresAt;
        this.userId = userId;
        this.role = role;
        this.name = name;
        this.surname = surname;
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

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }
}

