package in.gov.ntro.sih.ms.repo;

import in.gov.ntro.sih.ms.domain.Capture;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CaptureRepository extends JpaRepository<Capture, Long> {
    List<Capture> findAllByOrderByUploadedAtDesc();
    List<Capture> findByInvestigationIdOrderByIdDesc(Long investigationId);
    List<Capture> findByStatusOrderByIdAsc(Capture.Status status);
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select c from Capture c where c.id = :id")
    Optional<Capture> lockById(@org.springframework.data.repository.query.Param("id") Long id);


    /** Uploading the same evidence twice should find the first analysis, not repeat it. */
    Optional<Capture> findFirstBySha256AndStatusOrderByIdDesc(String sha256, Capture.Status status);
}
