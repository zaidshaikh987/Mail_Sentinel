package in.gov.ntro.sih.ms.web;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.gov.ntro.sih.ms.domain.Asset;
import in.gov.ntro.sih.ms.domain.Capture;
import in.gov.ntro.sih.ms.domain.Finding;
import in.gov.ntro.sih.ms.domain.MailSession;
import in.gov.ntro.sih.ms.engine.EngineClient;
import in.gov.ntro.sih.ms.repo.AssetRepository;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import in.gov.ntro.sih.ms.repo.FindingRepository;
import in.gov.ntro.sih.ms.repo.MailSessionRepository;
import in.gov.ntro.sih.ms.service.AnalysisService;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * The REST surface the React dashboard talks to.
 *
 * <p>The read handlers are {@code @Transactional(readOnly = true)} on purpose.
 * {@code spring.jpa.open-in-view} is disabled — the right setting, because
 * leaving a persistence context open for the whole request hides N+1 queries
 * behind view rendering — but that means a handler which walks a lazy
 * association has no session unless it opens one. Without this, reading a
 * capture's sessions throws LazyInitializationException on the first access to
 * a session's findings.
 *
 * <p>Responses are shaped for the screens that consume them: a list view gets
 * summaries, a detail view gets everything, and the raw engine document is
 * available unmodified for anyone who wants the evidence rather than the view.
 */
@RestController
@RequestMapping("/api")
public class CaptureController {

    private final AnalysisService analysis;
    private final CaptureRepository captures;
    private final MailSessionRepository sessions;
    private final AssetRepository assets;
    private final FindingRepository findings;
    private final EngineClient engine;
    private final in.gov.ntro.sih.ms.service.JobState jobs;
    private final ObjectMapper mapper = new ObjectMapper();

    public CaptureController(AnalysisService analysis, CaptureRepository captures,
                             MailSessionRepository sessions, AssetRepository assets,
                             FindingRepository findings, EngineClient engine, in.gov.ntro.sih.ms.service.JobState jobs) {
        this.jobs = jobs;
        this.analysis = analysis;
        this.captures = captures;
        this.sessions = sessions;
        this.assets = assets;
        this.findings = findings;
        this.engine = engine;
    }

    // ---------------------------------------------------------------- health

    @GetMapping("/health")
    public Map<String, Object> health() {
        EngineClient.EngineStatus status = engine.probe();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", status.ready() ? "UP" : "DEGRADED");
        out.put("engine", status.ready() ? "ready" : "unavailable");
        out.put("engineVersion", status.version());
        // Which interpreter, and which Python. The two run modes install the
        // same engine but not necessarily onto the same Python version, so this
        // is the first thing worth knowing when one works and the other does not.
        out.put("python", status.python());
        out.put("interpreter", status.interpreter());
        if (!status.ready()) {
            out.put("error", status.error());
            // The overwhelmingly common cause is the configured interpreter not
            // being the one the engine was installed into, so say what to do
            // about it rather than just reporting a failure.
            out.put("hint", "The analysis engine is not installed in the interpreter this "
                    + "service is configured to use. From the project root:\n"
                    + "  ./scripts/setup.sh\n"
                    + "  export SMS_PYTHON=\"$PWD/.venv/bin/python\"\n"
                    + "then restart. That script is the same one the Docker image runs, so a "
                    + "container and a local run install the engine identically.");
        }
        return out;
    }

    // ---------------------------------------------------------------- upload

    @PostMapping(value = "/captures", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> upload(@RequestPart("file") MultipartFile file, @RequestParam(required=false) Long investigationId) {
        Capture capture = analysis.accept(file, investigationId);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "id", capture.getId(),
                "filename", capture.getFilename(),
                "sha256", capture.getSha256(),
                "status", capture.getStatus().name()));
    }

    /** Synchronous variant — convenient for scripting and for the test suite. */
    @PostMapping(value = "/captures/sync", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadSync(@RequestPart("file") MultipartFile file) {
        Capture capture = analysis.accept(file);
        capture = analysis.analyse(capture.getId());
        return ResponseEntity.ok(summary(capture));
    }

    /**
     * The bundled captures, offered on the upload screen so the tool can be
     * demonstrated without hunting for a pcap first.
     *
     * <p>Each carries the verdict it earns, so a viewer can pick the case they
     * want to see rather than clicking blind. The end-to-end suite analyses
     * every one of them and asserts the grade matches what is advertised here.
     */
    @GetMapping("/demo-captures")
    public List<AnalysisService.DemoCapture> demoCaptures() {
        return analysis.demoCaptures();
    }

    /**
     * Analyse one of the bundled captures.
     *
     * <p>Deliberately the same work as an upload — copied in, hashed, run
     * through the engine, persisted — so a demo exercises the production path
     * rather than a parallel one that can drift away from it.
     */
    @PostMapping("/captures/demo/{name}")
    public ResponseEntity<Map<String, Object>> analyseDemo(@PathVariable String name, @RequestParam(defaultValue="true") boolean sync, @RequestParam(required=false) Long investigationId) {
        Capture capture = analysis.acceptDemo(name, investigationId);
        if (sync) capture = analysis.analyse(capture.getId());
        return ResponseEntity.status(sync ? HttpStatus.OK : HttpStatus.ACCEPTED).body(summary(capture));
    }

    // ------------------------------------------------------------------ read

    @GetMapping("/captures")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> list() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Capture c : captures.findAllByOrderByUploadedAtDesc()) {
            out.add(summary(c));
        }
        return out;
    }

    @GetMapping("/captures/{id}")
    @Transactional(readOnly = true)
    public Map<String, Object> detail(@PathVariable Long id) {
        Capture c = require(id);
        Map<String, Object> out = summary(c);
        out.put("assets", assets.findByCaptureIdOrderByExposureScoreDesc(id)
                .stream().map(CaptureController::assetView).toList());
        out.put("sessions", sessions.findByCaptureIdOrderByStreamIndexAsc(id)
                .stream().map(CaptureController::sessionSummary).toList());
        out.put("remediation", remediation(c));
        out.put("warnings", warnings(c));
        JsonNode raw = parse(c);
        if (raw != null) {
            out.put("report", raw);
            out.put("coverage", raw.path("coverage")); out.put("provenance", raw.path("provenance"));
            out.put("history", raw.path("history"));
        }
        return out;
    }

    @GetMapping("/captures/{id}/sessions")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> sessionList(@PathVariable Long id) {
        require(id);
        return sessions.findByCaptureIdOrderByStreamIndexAsc(id)
                .stream().map(CaptureController::sessionSummary).toList();
    }

    @GetMapping("/captures/{captureId}/sessions/{sessionId}")
    @Transactional(readOnly = true)
    public Map<String, Object> sessionDetail(@PathVariable Long captureId,
                                             @PathVariable Long sessionId) {
        MailSession s = sessions.findById(sessionId)
                .orElseThrow(() -> new IllegalArgumentException("no session " + sessionId));
        Map<String, Object> out = sessionSummary(s);
        out.put("findings", findings.findBySessionId(sessionId)
                .stream().map(CaptureController::findingView).toList());
        // The engine document holds the parts too detailed for the schema:
        // the transcript, the SHAP contributions and the full certificate chain.
        if (!s.getCapture().getId().equals(captureId)) throw new IllegalArgumentException("Session does not belong to this capture");
        JsonNode raw = engineSession(require(captureId), s.getStreamIndex());
        if (raw != null) {
            out.put("transcript", raw.path("command_transcript"));
            out.put("chain", raw.path("chain"));
            out.put("ml", raw.path("ml"));
            out.put("capabilityLine", raw.path("capability_line").asText(null));
            out.put("mangledToken", raw.path("mangled_token").asText(null));
            out.put("notes", raw.path("notes"));
            out.put("coverage", raw.path("coverage"));
        }
        return out;
    }

    @GetMapping("/captures/{id}/assets")
    @Transactional(readOnly = true)
    public List<Map<String, Object>> assetList(@PathVariable Long id) {
        require(id);
        return assets.findByCaptureIdOrderByExposureScoreDesc(id)
                .stream().map(CaptureController::assetView).toList();
    }

    // --------------------------------------------------------------- exports

    /** The engine's document, byte-for-byte. This is the machine-readable deliverable. */
    @GetMapping(value = "/captures/{id}/report.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional(readOnly = true)
    public ResponseEntity<String> reportJson(@PathVariable Long id) {
        Capture c = require(id);
        if (c.getReportJson() == null) {
            throw new IllegalArgumentException("capture " + id + " has no completed analysis");
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"mailsentinel-" + id + ".json\"")
                .body(c.getReportJson());
    }

    /**
     * The same report as a self-contained HTML page.
     *
     * <p>Inline rather than an attachment, because this is meant to be opened.
     * Adding {@code ?print=1} makes the page print itself, which is how "save
     * as PDF" works — the report carries the {@code @page} rules, so the
     * browser produces the same document a server-side renderer would, on any
     * machine, with nothing installed.
     */
    @GetMapping(value = "/captures/{id}/report.html", produces = MediaType.TEXT_HTML_VALUE)
    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> reportHtml(@PathVariable Long id) {
        byte[] body = engine.render(requireReport(id));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "inline; filename=\"mailsentinel-" + id + ".html\"")
                .contentType(MediaType.TEXT_HTML)
                .body(body);
    }


    private String requireReport(Long id) {
        Capture c = require(id);
        if (c.getReportJson() == null) {
            throw new IllegalArgumentException("capture " + id + " has no completed analysis");
        }
        return c.getReportJson();
    }

    @PostMapping("/captures/{id}/cancel")
    public Map<String, Object> cancel(@PathVariable Long id) { return summary(jobs.cancel(id)); }

    @PostMapping("/captures/{id}/retry")
    public Map<String, Object> retry(@PathVariable Long id) { return summary(jobs.retry(id)); }

    @DeleteMapping("/captures/{id}")
    @Transactional
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        Capture c = require(id);
        if (c.getStatus() == Capture.Status.RUNNING || c.getStatus() == Capture.Status.PENDING)
            throw new IllegalArgumentException("Cancel the active run before deleting it");
        captures.delete(c);
        return ResponseEntity.noContent().build();
    }

    // ------------------------------------------------------------------ views

    private Capture require(Long id) {
        return captures.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("no capture " + id));
    }

    public static Map<String, Object> summary(Capture c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("investigationId", c.getInvestigationId());
        m.put("sourceCaptureId", c.getSourceCaptureId());
        m.put("stage", c.getStage());
        m.put("startedAt", c.getStartedAt());
        m.put("filename", c.getFilename());
        m.put("sha256", c.getSha256());
        m.put("sizeBytes", c.getSizeBytes());
        m.put("format", c.getFormat());
        m.put("packetCount", c.getPacketCount());
        m.put("capturedAt", c.getCapturedAt());
        m.put("uploadedAt", c.getUploadedAt());
        m.put("analysedAt", c.getAnalysedAt());
        m.put("status", c.getStatus().name());
        m.put("errorMessage", c.getErrorMessage());
        m.put("overallGrade", c.getOverallGrade());
        m.put("overallScore", c.getOverallScore());
        m.put("counts", Map.of(
                "critical", nz(c.getCriticalCount()),
                "high", nz(c.getHighCount()),
                "medium", nz(c.getMediumCount()),
                "low", nz(c.getLowCount()),
                "sessions", nz(c.getSessionCount()),
                "assets", nz(c.getAssetCount()),
                "credentialsExposed", nz(c.getCredentialsExposed())));
        return m;
    }

    private static Map<String, Object> sessionSummary(MailSession s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", s.getId());
        m.put("stream", s.getStreamIndex());
        m.put("firstFrame", s.getFirstFrame());
        m.put("lastFrame", s.getLastFrame());
        m.put("protocol", s.getProtocol());
        m.put("role", s.getRole());
        m.put("tlsMode", s.getTlsMode());
        m.put("client", s.getClientIp() + ":" + s.getClientPort());
        m.put("server", s.getServerIp() + ":" + s.getServerPort());
        m.put("serverName", s.getServerName());
        m.put("tlsVersion", s.getTlsVersion());
        m.put("cipherSuite", s.getCipherSuite());
        m.put("keyExchange", s.getKeyExchange());
        m.put("keyExchangeBits", s.getKeyExchangeBits());
        m.put("forwardSecrecy", s.getForwardSecrecy());
        m.put("certVisibility", s.getCertVisibility());
        m.put("certSubject", s.getCertSubject());
        m.put("certIssuer", s.getCertIssuer());
        m.put("certSelfSigned", s.getCertSelfSigned());
        m.put("certExpiredAtCapture", s.getCertExpiredAtCapture());
        m.put("chainValid", s.getChainValid());
        m.put("starttlsOffered", s.getStarttlsOffered());
        m.put("starttlsRequested", s.getStarttlsRequested());
        m.put("starttlsAccepted", s.getStarttlsAccepted());
        m.put("capabilityMangled", s.getCapabilityMangled());
        m.put("cleartextAuth", s.getCleartextAuth());
        m.put("exposedUsername", s.getExposedUsername());
        m.put("grade", s.getGrade());
        m.put("rawScore", s.getRawScore());
        m.put("cappedBy", s.getCappedBy());
        m.put("trusted", s.getTrusted());
        m.put("confidence", s.getConfidence());
        m.put("ja3", s.getJa3());
        m.put("ja4", s.getJa4());
        m.put("mlRiskClass", s.getMlRiskClass());
        m.put("mlRiskScore", s.getMlRiskScore());
        m.put("mlAnomaly", s.getMlAnomaly());
        m.put("mlExplanation", s.getMlExplanation());
        m.put("findingCount", s.getFindings() == null ? 0 : s.getFindings().size());
        return m;
    }

    private static Map<String, Object> findingView(Finding f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ruleId", f.getRuleId());
        m.put("severity", f.getSeverity());
        m.put("title", f.getTitle());
        m.put("standard", f.getStandard());
        m.put("remediation", f.getRemediation());
        m.put("detail", f.getDetail());
        m.put("capGrade", f.getCapGrade());
        m.put("frames", f.getEvidenceFrames());
        return m;
    }

    private static Map<String, Object> assetView(Asset a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", a.getId());
        m.put("key", a.getAssetKey());
        m.put("host", a.getHost());
        m.put("port", a.getPort());
        m.put("protocol", a.getProtocol());
        m.put("role", a.getRole());
        m.put("grade", a.getGrade());
        m.put("rawScore", a.getRawScore());
        m.put("cappedBy", a.getCappedBy());
        m.put("trusted", a.getTrusted());
        m.put("sessionCount", a.getSessionCount());
        m.put("distinctClients", a.getDistinctClients());
        m.put("bestTls", a.getBestTls());
        m.put("worstTls", a.getWorstTls());
        m.put("versionSpread", a.getVersionSpread());
        m.put("credentialsExposed", a.getCredentialsExposed());
        m.put("exposureScore", a.getExposureScore());
        m.put("mlRisk", a.getMlRisk());
        return m;
    }

    private JsonNode remediation(Capture c) {
        JsonNode root = parse(c);
        return root == null ? mapper.createArrayNode() : root.path("remediation");
    }

    private JsonNode warnings(Capture c) {
        JsonNode root = parse(c);
        return root == null ? mapper.createArrayNode() : root.path("warnings");
    }

    private JsonNode engineSession(Capture c, int stream) {
        JsonNode root = parse(c);
        if (root == null) {
            return null;
        }
        for (JsonNode s : root.path("sessions")) {
            if (s.path("tcp_stream").asInt(-1) == stream) {
                return s;
            }
        }
        return null;
    }

    private JsonNode parse(Capture c) {
        if (c.getReportJson() == null) {
            return null;
        }
        try {
            return mapper.readTree(c.getReportJson());
        } catch (Exception e) {
            return null;
        }
    }

    private static int nz(Integer v) {
        return v == null ? 0 : v;
    }
}
