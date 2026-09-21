package in.gov.ntro.sih.ms.repo;

import in.gov.ntro.sih.ms.domain.Finding;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface FindingRepository extends JpaRepository<Finding, Long> {
    List<Finding> findBySessionId(Long sessionId);

    /** Rule frequency across a capture — drives the "fix this once, on four servers" view. */
    @Query("""
           select f.ruleId, f.title, f.severity, count(f)
           from Finding f
           where f.session.capture.id = :captureId
           group by f.ruleId, f.title, f.severity
           order by count(f) desc
           """)
    List<Object[]> countByRuleForCapture(Long captureId);
}
