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
public class LoginResponse {
    private String accessToken;
    private OffsetDateTime accessExpiresAt;
    private String refreshToken;
    private OffsetDateTime refreshExpiresAt;
    private String userId;
    private String role;
    private String name;
    private String surname;
}
