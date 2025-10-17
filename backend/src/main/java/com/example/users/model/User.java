package com.example.users.model;

import com.example.buildingBlocks.BaseEntity;
import com.example.certificates.model.Certificate;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

import java.time.OffsetDateTime;
import java.util.List;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class User extends BaseEntity {

    @NotNull
    @Enumerated(EnumType.STRING)
    private Role role;

    @Size(max = 100)
    private String name;

    @Size(max = 100)
    private String surname;

    @Size(max = 150)
    private String organization;

    @NotBlank
    @Email
    @Column(nullable = false, unique = true)
    private String email;

    @NotNull
    private Boolean emailConfirmed;

    @NotBlank
    private String hashedPassword;

    @NotBlank
    private String refreshToken;

    private OffsetDateTime refreshTokenExpiresAt;

    @NotEmpty
    @OneToMany(mappedBy = "owner", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Certificate> myCertificates;
}
