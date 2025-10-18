package rs.ac.uns.ftn.pki.certificates.service;


import rs.ac.uns.ftn.pki.certificates.model.*;
import org.springframework.stereotype.Service;

@Service
public interface CertificateService {
    CertificateStatus getStatus(Certificate certificate);
}
