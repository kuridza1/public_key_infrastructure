package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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

    public static NamesConstraintsValue fromNameConstraints(NameConstraints nc) {
        if (nc == null) return new NamesConstraintsValue();

        GeneralSubtree[] permittedSubtrees = nc.getPermittedSubtrees();
        GeneralSubtree[] excludedSubtrees = nc.getExcludedSubtrees();

        ListOfNames permittedList = fromSubtrees(permittedSubtrees);
        ListOfNames excludedList = fromSubtrees(excludedSubtrees);

        return new NamesConstraintsValue(permittedList, excludedList);
    }

    private static ListOfNames fromSubtrees(GeneralSubtree[] subtrees) {
        if (subtrees == null || subtrees.length == 0) return null;

        GeneralName[] names = Arrays.stream(subtrees)
                .filter(Objects::nonNull)
                .map(GeneralSubtree::getBase)
                .toArray(GeneralName[]::new);

        if (names.length == 0) return null;

        return ListOfNames.fromGeneralNames(new GeneralNames(names));
    }

    /** Converts this DTO back to a BouncyCastle NameConstraints object. */
    public NameConstraints toNameConstraints() {
        GeneralSubtree[] permittedArr = toSubtreeArray(permitted);
        GeneralSubtree[] excludedArr = toSubtreeArray(excluded);
        return new NameConstraints(permittedArr, excludedArr);
    }

    private static GeneralSubtree[] toSubtreeArray(ListOfNames list) {
        if (list == null) return null;
        List<GeneralSubtree> subtrees = list.toGeneralSubtrees();
        if (subtrees == null || subtrees.isEmpty()) return null;
        return subtrees.toArray(new GeneralSubtree[0]);
    }
}