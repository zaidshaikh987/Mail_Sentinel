package in.gov.ntro.sih.ms.repo;
import in.gov.ntro.sih.ms.domain.Investigation;
import org.springframework.data.jpa.repository.JpaRepository;
public interface InvestigationRepository extends JpaRepository<Investigation, Long> {}
