package rs.ac.uns.ftn.pki.certificates.model.extensionValues;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;

import java.util.ArrayList;
import java.util.List;

public class NameConstraintsExtensions {

    public static NamesConstraintsValue toNamesConstraintsValue(NameConstraints nameConstraints) {
        ListOfNames permitted = new ListOfNames();
        permitted.setValue("");
        ListOfNames excluded = new ListOfNames();
        excluded.setValue("");

        // ----- Permitted subtrees -----
        if (nameConstraints.getPermittedSubtrees() != null) {
            List<String> permittedList = new ArrayList<>();
            ASN1Sequence permittedSubtrees = ASN1Sequence.getInstance(nameConstraints.getPermittedSubtrees());

            for (int i = 0; i < permittedSubtrees.size(); i++) {
                GeneralSubtree gs = GeneralSubtree.getInstance(permittedSubtrees.getObjectAt(i));
                GeneralNames generalNames = new GeneralNames(gs.getBase());
                // ✅ use ListOfNames.fromGeneralNames instead of GeneralNamesExtensions
                ListOfNames listOfNames = ListOfNames.fromGeneralNames(generalNames);
                permittedList.add(listOfNames.getValue());
            }
            permitted.setValue(String.join(",", permittedList));
        }

        // ----- Excluded subtrees -----
        if (nameConstraints.getExcludedSubtrees() != null) {
            List<String> excludedList = new ArrayList<>();
            ASN1Sequence excludedSubtrees = ASN1Sequence.getInstance(nameConstraints.getExcludedSubtrees());

            for (int i = 0; i < excludedSubtrees.size(); i++) {
                GeneralSubtree gs = GeneralSubtree.getInstance(excludedSubtrees.getObjectAt(i));
                GeneralNames generalNames = new GeneralNames(gs.getBase());
                // ✅ use ListOfNames.fromGeneralNames instead of GeneralNamesExtensions
                ListOfNames listOfNames = ListOfNames.fromGeneralNames(generalNames);
                excludedList.add(listOfNames.getValue());
            }
            excluded.setValue(String.join(",", excludedList));
        }

        return new NamesConstraintsValue(permitted, excluded);
    }
}
