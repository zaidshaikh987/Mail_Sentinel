package in.gov.ntro.sih.ms.config;

import in.gov.ntro.sih.ms.domain.Role;
import in.gov.ntro.sih.ms.domain.User;
import in.gov.ntro.sih.ms.repo.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            userRepository.save(new User("analyst", passwordEncoder.encode("password"), Role.ROLE_SOC_ANALYST));
            userRepository.save(new User("auditor", passwordEncoder.encode("password"), Role.ROLE_AUDITOR));
            userRepository.save(new User("admin", passwordEncoder.encode("password"), Role.ROLE_ADMIN));
        }
    }
}
