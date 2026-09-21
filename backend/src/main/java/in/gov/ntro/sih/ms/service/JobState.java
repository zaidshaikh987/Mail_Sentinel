package in.gov.ntro.sih.ms.service;
import in.gov.ntro.sih.ms.domain.Capture;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import in.gov.ntro.sih.ms.repo.InvestigationRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Instant;

/** Short committed transactions; no database transaction wraps the Python process. */
@Service
public class JobState {
    private final CaptureRepository captures;
    private final InvestigationRepository investigations;
    public JobState(CaptureRepository captures, InvestigationRepository investigations) {
        this.captures = captures; this.investigations = investigations;
    }
    @Transactional
    public Capture claim(Long id) {
        Capture c = captures.lockById(id).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (c.getStatus() != Capture.Status.PENDING) return null;
        c.setStatus(Capture.Status.RUNNING); c.setStage("STARTING"); c.setStartedAt(Instant.now());
        return captures.save(c);
    }
    @Transactional
    public void progress(Long id, String stage) {
        Capture c = captures.lockById(id).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (c.getStatus() == Capture.Status.RUNNING) c.setStage(stage);
    }
    public boolean cancelled(Long id) {
        return captures.findById(id).map(c -> c.getStatus() == Capture.Status.CANCELLED).orElse(true);
    }
    @Transactional
    public Capture cancel(Long id) {
        Capture c = captures.lockById(id).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (c.getStatus() == Capture.Status.PENDING || c.getStatus() == Capture.Status.RUNNING) {
            c.setStatus(Capture.Status.CANCELLED); c.setStage("CANCELLED");
        }
        return c;
    }
    @Transactional
    public Capture assign(Long id, Long investigationId) {
        if (investigationId != null && !investigations.existsById(investigationId))
            throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Investigation not found");
        Capture c = captures.lockById(id).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (c.getStatus() != Capture.Status.PENDING) throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Only queued runs may be assigned");
        c.setInvestigationId(investigationId); return c;
    }
    @Transactional
    public Capture retry(Long id) {
        Capture old = captures.lockById(id).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (old.getStatus() == Capture.Status.RUNNING || old.getStatus() == Capture.Status.PENDING)
            throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Wait for the current run or cancel it first");
        Capture c = new Capture();
        c.setFilename(old.getFilename()); c.setStoragePath(old.getStoragePath());
        c.setSha256(old.getSha256()); c.setSizeBytes(old.getSizeBytes());
        c.setInvestigationId(old.getInvestigationId()); c.setSourceCaptureId(old.getId());
        return captures.save(c);
    }
    @Transactional
    public void recoverInterrupted() {
        for (Capture c : captures.findByStatusOrderByIdAsc(Capture.Status.RUNNING)) {
            c.setStatus(Capture.Status.FAILED); c.setStage("INTERRUPTED");
            c.setErrorMessage("Service restarted during analysis. Retry creates a new run; the original evidence is retained.");
        }
    }
}
