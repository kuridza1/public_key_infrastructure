package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

public class NamesConstraintsValue {
    private ListOfNames permitted;
    private ListOfNames excluded;

    // Constructors
    public NamesConstraintsValue() {}

    public NamesConstraintsValue(ListOfNames permitted, ListOfNames excluded) {
        this.permitted = permitted;
        this.excluded = excluded;
    }

    // Getters and Setters
    public ListOfNames getPermitted() {
        return permitted;
    }

    public void setPermitted(ListOfNames permitted) {
        this.permitted = permitted;
    }

    public ListOfNames getExcluded() {
        return excluded;
    }

    public void setExcluded(ListOfNames excluded) {
        this.excluded = excluded;
    }

    @Override
    public String toString() {
        return "NamesConstraintsValue{" +
                "permitted=" + permitted +
                ", excluded=" + excluded +
                '}';
    }
}