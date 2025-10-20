package rs.ac.uns.ftn.pki.users.repository;

import rs.ac.uns.ftn.pki.users.model.Role;
import rs.ac.uns.ftn.pki.users.model.User;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    boolean existsByEmail(String email);

    List<User> findAllByRole(Role role);

    @Query("""

            select distinct u from User u
           left join fetch u.myCertificates c
           where u.role = :role
           """)
    List<User> findAllByRoleWithCertificates(@Param("role") Role role);

    User findByEmail(String email);

    @EntityGraph(attributePaths = "myCertificates")
    Optional<User> findWithMyCertificatesById(UUID id);


    Optional<User> findByIdAndRole(UUID id, Role role);

    @EntityGraph(attributePaths = {"myCertificates"})
    Optional<User> findWithMyCertificatesByIdAndRole(UUID id, Role role);

}
