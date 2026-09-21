package in.gov.ntro.sih.ms.service;
import in.gov.ntro.sih.ms.domain.Capture;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Single-instance durable database queue, one resource-bounded subprocess at a time. */
@Component
@EnableScheduling
@ConditionalOnProperty(name="ms.jobs.enabled", havingValue="true", matchIfMissing=true)
public class AnalysisQueue {
    private final CaptureRepository captures;
    private final AnalysisService analysis;
    private final JobState jobs;
    private volatile boolean ready;
    public AnalysisQueue(CaptureRepository captures, AnalysisService analysis, JobState jobs) {
        this.captures = captures; this.analysis = analysis; this.jobs = jobs;
    }
    @EventListener(ApplicationReadyEvent.class)
    public void start() { jobs.recoverInterrupted(); ready = true; }
    @Scheduled(fixedDelay=1000)
    public void poll() {
        if (!ready) return;
        captures.findByStatusOrderByIdAsc(Capture.Status.PENDING).stream().findFirst()
                .ifPresent(c -> analysis.analyse(c.getId()));
    }
}
