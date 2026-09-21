package in.gov.ntro.sih.ms.repo;

import in.gov.ntro.sih.ms.domain.MailSession;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MailSessionRepository extends JpaRepository<MailSession, Long> {
    List<MailSession> findByCaptureIdOrderByStreamIndexAsc(Long captureId);
    List<MailSession> findByCaptureIdAndGrade(Long captureId, String grade);
}
