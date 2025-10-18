package rs.ac.uns.ftn.pki.users.model;

import rs.ac.uns.ftn.pki.buildingBlocks.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
public class VerificationToken extends BaseEntity {

    @NotNull
    private UUID userId;

    @NotNull
    @Enumerated(EnumType.STRING)
    private VerificationPurpose purpose;

    @NotBlank
    @Column(nullable = false, length = 512)
    private String tokenHashHex;

    @NotNull
    private OffsetDateTime expiresAt;

    private OffsetDateTime usedAt;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_ref_id",
            referencedColumnName = "id",
            foreignKey = @ForeignKey(name = "fk_vtoken_user")
    )
    private User user;

    // --- Getters and Setters ---

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public VerificationPurpose getPurpose() {
        return purpose;
    }

    public void setPurpose(VerificationPurpose purpose) {
        this.purpose = purpose;
    }

    public String getTokenHashHex() {
        return tokenHashHex;
    }

    public void setTokenHashHex(String tokenHashHex) {
        this.tokenHashHex = tokenHashHex;
    }

    public OffsetDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(OffsetDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public OffsetDateTime getUsedAt() {
        return usedAt;
    }

    public void setUsedAt(OffsetDateTime usedAt) {
        this.usedAt = usedAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
