package rs.ac.uns.ftn.pki.users.dtos.responses;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RefreshResponse {
    private String accessToken;
    private OffsetDateTime accessExpiresAt;
    private String refreshToken;
    private OffsetDateTime refreshExpiresAt;
    private String userId;
}
