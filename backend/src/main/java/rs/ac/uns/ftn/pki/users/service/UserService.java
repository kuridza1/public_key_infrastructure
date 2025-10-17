package rs.ac.uns.ftn.pki.users.service;

import rs.ac.uns.ftn.pki.certificates.model.CertificateStatus;
import rs.ac.uns.ftn.pki.certificates.service.CertificateService;
import rs.ac.uns.ftn.pki.users.dtos.responses.CaUserResponse;
import rs.ac.uns.ftn.pki.users.model.Role;
import rs.ac.uns.ftn.pki.users.repository.UserRepository;
import rs.ac.uns.ftn.pki.users.model.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import rs.ac.uns.ftn.pki.certificates.model.Certificate;
import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepo;
    private final CertificateService certificateService;

    public UserService(UserRepository userRepo, CertificateService certificateService) {
        this.userRepo = userRepo;
        this.certificateService = certificateService;
    }

    @Transactional(readOnly = true)
    public List<CaUserResponse> getAllCaUsers() {
        List<User> users = userRepo.findAllByRole(Role.CaUser);
        return users.stream().map(u -> {
            CaUserResponse dto = new CaUserResponse();
            dto.setId(u.getId().toString());
            dto.setEmail(u.getEmail());
            dto.setName(u.getName());
            dto.setSurname(u.getSurname());
            dto.setOrganization(u.getOrganization());
            return dto;
        }).toList();
    }

    @Transactional(readOnly = true)
    public List<CaUserResponse> getValidCaUsers() {
        List<User> users = userRepo.findAllByRoleWithCertificates(Role.CaUser);

        return users.stream()
                .map(u -> {
                    var active = u.getMyCertificates().stream()
                            .filter(c -> certificateService.getStatus(c) == CertificateStatus.ACTIVE)
                            .toList();

                    if (active.isEmpty()) return null;

                    OffsetDateTime minFrom = active.stream()
                            .map(Certificate::getNotBefore)
                            .min(Comparator.naturalOrder())
                            .orElse(null);

                    OffsetDateTime maxUntil = active.stream()
                            .map(Certificate::getNotAfter)
                            .max(Comparator.naturalOrder())
                            .orElse(null);

                    CaUserResponse dto = new CaUserResponse();
                    dto.setId(u.getId().toString());
                    dto.setEmail(u.getEmail());
                    dto.setName(u.getName());
                    dto.setSurname(u.getSurname());
                    dto.setOrganization(u.getOrganization());
                    dto.setMinValidFrom(minFrom);
                    dto.setMaxValidUntil(maxUntil);
                    return dto;
                })
                .filter(dto -> dto != null)
                .toList();
    }
}
