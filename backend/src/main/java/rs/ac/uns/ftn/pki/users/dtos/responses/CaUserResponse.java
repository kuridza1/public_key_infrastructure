package rs.ac.uns.ftn.pki.users.dtos.responses;

import rs.ac.uns.ftn.pki.users.model.User;
import java.time.OffsetDateTime;

public class CaUserResponse {

    private String id;
    private String email;
    private String name;
    private String surname;
    private String organization;
    private OffsetDateTime minValidFrom;
    private OffsetDateTime maxValidUntil;

    public CaUserResponse() {
    }

    public CaUserResponse(User u) {
        this.id = u.getId().toString();
        this.email = u.getEmail();
        this.name = u.getName();
        this.surname = u.getSurname();
        this.organization = u.getOrganization();
    }

    // --- Getters and Setters ---

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public OffsetDateTime getMinValidFrom() {
        return minValidFrom;
    }

    public void setMinValidFrom(OffsetDateTime minValidFrom) {
        this.minValidFrom = minValidFrom;
    }

    public OffsetDateTime getMaxValidUntil() {
        return maxValidUntil;
    }

    public void setMaxValidUntil(OffsetDateTime maxValidUntil) {
        this.maxValidUntil = maxValidUntil;
    }
}
