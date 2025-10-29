// src/main/java/rs/ac/uns/ftn/pki/security/FileMasterKeyProvider.java
package rs.ac.uns.ftn.pki.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

public interface MasterKeyProvider {
    byte[] getMasterKeyForOrg(String orgId); // 32 bytes for AES-256, for example
}


