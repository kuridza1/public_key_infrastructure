package rs.ac.uns.ftn.pki.certificates.utils;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import java.math.BigInteger;

@Converter(autoApply = true)
public class BigIntegerConverter implements AttributeConverter<BigInteger, String> {

    @Override
    public String convertToDatabaseColumn(BigInteger attribute) {
        return attribute != null ? attribute.toString() : null;
    }

    @Override
    public BigInteger convertToEntityAttribute(String dbData) {
        return dbData != null ? new BigInteger(dbData) : null;
    }
}
