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
           left join fetch u.issuedCertificates c
           where u.role = :role
           """)
    List<User> findAllByRoleWithCertificates(@Param("role") Role role);

    @Query("""
           select distinct u from User u
           left join fetch u.issuedCertificates
           where u.id = :id
           """)
    Optional<User> findByIdWithCertificates(@Param("id") UUID id);

    @Query("""
           select distinct u from User u
           left join fetch u.issuedCertificates
           where u.email = :email
           """)
    Optional<User> findByEmailWithCertificates(@Param("email") String email);

    @Query("""
           select case when count(c) > 0 then true else false end
           from User u join u.issuedCertificates c
           where u.id = :userId and c.serialNumber = :certificateSerialNumber
           """)
    boolean userHasCertificate(@Param("userId") UUID userId,
                               @Param("certificateSerialNumber") java.math.BigInteger certificateSerialNumber);
    User findByEmail(String email);

    @EntityGraph(attributePaths = "issuedCertificates")
    Optional<User> findWithMyCertificatesById(UUID id);


    Optional<User> findByIdAndRole(UUID id, Role role);

    @EntityGraph(attributePaths = {"issuedCertificates"})
    Optional<User> findWithMyCertificatesByIdAndRole(UUID id, Role role);

}
