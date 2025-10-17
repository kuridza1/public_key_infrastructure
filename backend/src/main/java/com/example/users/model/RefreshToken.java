package com.example.users.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @NotNull
    private UUID userId;

    @NotBlank
    @Column(nullable = false, length = 512)
    private String tokenHashHex;

    @NotNull
    private OffsetDateTime createdAt;

    @NotNull
    private OffsetDateTime expiresAt;

    private OffsetDateTime consumedAt;

    private OffsetDateTime revokedAt;

    @Size(max = 512)
    private String replacedByHashHex;

    // Optional telemetry
    @Size(max = 100)
    private String deviceId;

    @Size(max = 45) // supports IPv4 and IPv6
    private String ip;

    @Size(max = 255)
    private String userAgent;
}
