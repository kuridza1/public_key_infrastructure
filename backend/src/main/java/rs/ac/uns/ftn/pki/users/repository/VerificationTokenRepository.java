package rs.ac.uns.ftn.pki.users.repository;


import rs.ac.uns.ftn.pki.users.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, UUID> { }

