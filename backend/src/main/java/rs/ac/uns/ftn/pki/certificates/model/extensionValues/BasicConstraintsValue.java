package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import java.util.Objects;

public class BasicConstraintsValue {
    private boolean isCa;
    private Integer pathLen;

    // Default constructor
    public BasicConstraintsValue() {}

    // Constructor with parameters
    public BasicConstraintsValue(boolean isCa, Integer pathLen) {
        this.isCa = isCa;
        this.pathLen = pathLen;
    }

    // Getter and Setter for isCa
    public boolean getIsCa() {
        return isCa;
    }

    public void setIsCa(boolean isCa) {
        this.isCa = isCa;
    }

    public Integer getPathLen() {
        return pathLen;
    }

    public void setPathLen(Integer pathLen) {
        this.pathLen = pathLen;
    }

    // Optional: Override toString() for better debugging
    @Override
    public String toString() {
        return "BasicConstraintsValue{" +
                "isCa=" + isCa +
                ", pathLen=" + pathLen +
                '}';
    }

    // Optional: Override equals() and hashCode() if needed for comparisons
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BasicConstraintsValue that = (BasicConstraintsValue) o;
        return isCa == that.isCa &&
                Objects.equals(pathLen, that.pathLen);
    }

    @Override
    public int hashCode() {
        return Objects.hash(isCa, pathLen);
    }
}