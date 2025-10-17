package rs.ac.uns.ftn.pki;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import rs.ac.uns.ftn.pki.users.utils.FileCommonPasswordStore;
import rs.ac.uns.ftn.pki.users.utils.ICommonPasswordStore;

@Configuration
public class AppConfig {

    @Bean
    public ICommonPasswordStore commonPasswordStore() throws Exception {
        // Load from classpath (works in both dev and packaged JAR)
        Resource resource = new ClassPathResource("common_passwords.txt");
        return new FileCommonPasswordStore(resource, true);
    }
}
