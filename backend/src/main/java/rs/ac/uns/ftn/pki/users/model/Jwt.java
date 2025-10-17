package rs.ac.uns.ftn.pki.users.model;

import rs.ac.uns.ftn.pki.buildingBlocks.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import java.time.OffsetDateTime;
import java.util.UUID;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Jwt extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID jwtId;

    @NotBlank
    @Column(nullable = false, length = 1024)
    private String token;

    @NotNull
    private OffsetDateTime expiresAt;

    @NotNull
    private OffsetDateTime issuedAt;

    @NotNull
    private UUID userId;

    @NotNull
    @Enumerated(EnumType.STRING)
    private Role userRole;
}
