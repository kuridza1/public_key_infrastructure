package rs.ac.uns.ftn.pki.users.utils;

import org.springframework.stereotype.Component;

public interface ICommonPasswordStore {
    boolean contains(String candidate);
}
