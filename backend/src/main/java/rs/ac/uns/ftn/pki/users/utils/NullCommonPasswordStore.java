package rs.ac.uns.ftn.pki.users.utils;

public class NullCommonPasswordStore implements ICommonPasswordStore {
    @Override
    public boolean contains(String candidate) { return false; }
}
