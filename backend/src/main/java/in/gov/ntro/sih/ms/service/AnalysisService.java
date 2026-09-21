package in.gov.ntro.sih.ms.service;

import com.fasterxml.jackson.databind.JsonNode;
import in.gov.ntro.sih.ms.domain.Asset;
import in.gov.ntro.sih.ms.domain.Capture;
import in.gov.ntro.sih.ms.domain.Finding;
import in.gov.ntro.sih.ms.domain.MailSession;
import in.gov.ntro.sih.ms.engine.EngineClient;
import in.gov.ntro.sih.ms.engine.EngineProperties;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.StringJoiner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

/**
 * Upload, analyse, persist.
 *
 * <p>The mapping below is the one place the engine's JSON shape is interpreted.
 * Everything is read defensively — the engine is a separate program and a
 * missing optional field must never take down the API.
 */
@Service
public class AnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AnalysisService.class);

    private final CaptureRepository captures;
    private final EngineClient engine;
    private final EngineProperties properties;
    private final JobState jobs;
    private final org.springframework.transaction.support.TransactionTemplate transactions;

    public AnalysisService(CaptureRepository captures, EngineClient engine,
                           EngineProperties properties, JobState jobs, org.springframework.transaction.PlatformTransactionManager manager) {
        this.jobs = jobs;
        this.transactions = new org.springframework.transaction.support.TransactionTemplate(manager);
        this.captures = captures;
        this.engine = engine;
        this.properties = properties;
    }

    @Transactional
    public Capture accept(MultipartFile file, Long investigationId) {
        Capture c = accept(file);
        return jobs.assign(c.getId(), investigationId);
    }
    @Transactional
    public Capture acceptDemo(String name, Long investigationId) {
        Capture c = acceptDemo(name);
        return jobs.assign(c.getId(), investigationId);
    }

    public static class UploadRejected extends RuntimeException {
        public UploadRejected(String message) { super(message); }
    }

    /**
     * Store an uploaded capture and register it for analysis.
     *
     * <p>The SHA-256 is computed while the bytes are being written, before
     * anything else touches the file — that hash is the chain of custody the
     * whole report is anchored to.
     */
    @Transactional
    public Capture accept(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new UploadRejected("no file was uploaded");
        }
        if (file.getSize() > properties.getMaxUploadBytes()) {
            throw new UploadRejected("capture exceeds the "
                    + (properties.getMaxUploadBytes() / (1024 * 1024)) + " MB limit");
        }
        String original = sanitise(file.getOriginalFilename());
        if (!looksLikeCapture(original)) {
            throw new UploadRejected(
                    "expected a .pcap, .pcapng, .cap or .pcap.gz file, got '" + original + "'");
        }

        try (InputStream in = file.getInputStream()) {
            return store(in, original, file.getSize());
        } catch (IOException e) {
            throw new UploadRejected("could not read the upload: " + e.getMessage());
        }
    }

    /**
     * Register one of the bundled demo captures.
     *
     * <p>It is copied into the upload directory and hashed exactly like a file
     * a user dropped in, so it travels the same path through the same engine
     * and lands in the same tables. Nothing about a demo capture is special
     * once it is accepted — which is the point: the dashboard used to serve
     * pre-generated JSON for these, a second code path that could (and did)
     * behave differently from the real one.
     */
    @Transactional
    public Capture acceptDemo(String name) {
        String requested = sanitise(name);
        Path dir = properties.resolvedDemoDir();
        Path source = dir.resolve(requested).normalize();

        // The name arrives from a URL. Confine it to the demo directory.
        if (!source.startsWith(dir)) {
            throw new UploadRejected("'" + name + "' is not a bundled capture");
        }
        if (!Files.isRegularFile(source)) {
            throw new UploadRejected(
                    "no bundled capture named '" + requested + "' in " + dir);
        }
        if (!looksLikeCapture(requested)) {
            throw new UploadRejected("'" + requested + "' is not a capture file");
        }

        try (InputStream in = Files.newInputStream(source)) {
            return store(in, requested, Files.size(source));
        } catch (IOException e) {
            throw new UploadRejected("could not read " + source + ": " + e.getMessage());
        }
    }

    /**
     * Write bytes to the upload directory, hashing them on the way through.
     *
     * <p>The digest is computed from the same stream that is being written, so
     * the hash provably describes the stored file rather than a re-read of it.
     */
    private Capture store(InputStream in, String original, long size) {
        Path dir = properties.resolvedUploadDir();
        String stored;
        String digest;
        try {
            Files.createDirectories(dir);
            Path target = dir.resolve(java.util.UUID.randomUUID() + "-" + original);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (DigestInputStream dis = new DigestInputStream(in, md)) {
                Files.copy(dis, target, StandardCopyOption.REPLACE_EXISTING);
            }
            digest = HexFormat.of().formatHex(md.digest());
            stored = target.toAbsolutePath().toString();
            if (org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive()) {
                org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
                    new org.springframework.transaction.support.TransactionSynchronization() {
                        @Override public void afterCompletion(int status) {
                            if (status != STATUS_COMMITTED) try { Files.deleteIfExists(target); } catch (IOException e) { log.warn("Could not remove rolled-back upload {}", target); }
                        }
                    });
            }
        } catch (IOException e) {
            throw new UploadRejected("could not store the capture: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }

        Capture capture = new Capture();
        capture.setFilename(original);
        capture.setSha256(digest);
        capture.setSizeBytes(size);
        capture.setStatus(Capture.Status.PENDING);
        capture.setReportJson(null);
        capture.setStoragePath(stored);
        return captures.save(capture);
    }

    /**
     * One bundled capture offered on the front page.
     *
     * @param name  the file in demo-pcaps/
     * @param grade the verdict it earns — advertised so someone can pick the
     *              case they want to see, and pinned by a test so the button
     *              cannot come to disagree with the analysis behind it
     */
    public record DemoCapture(String name, String grade, String title, String note) {}

    /**
     * The demo set: five captures, ordered worst to best.
     *
     * <p>Curated rather than a directory listing, for two reasons. The order is
     * the argument — walking F, F, C, C, A+ shows the scale, where an
     * alphabetical list opens on a C and buries the A+ in the middle. And
     * demo-pcaps/ also holds fixtures the test suite needs that add nothing to
     * a demonstration: {@code sample-imf.pcap.gz} is a third cleartext-SMTP
     * failure that says the same thing as {@code smtp.pcap} while exercising
     * gzip handling, which matters to the tests and to nobody watching.
     *
     * <p>Two failures, two partial passes, one clean result. A tool that only
     * ever shows failures gives a viewer no way to tell a strict grader from a
     * broken one.
     */
    private static final List<DemoCapture> DEMOS = List.of(
            new DemoCapture("smtp.pcap", "F",
                    "SMTP relay with credentials in the clear",
                    "The server advertised STARTTLS on port 25; the client ignored it and sent "
                            + "AUTH LOGIN anyway. This capture exposes a working password."),
            new DemoCapture("imap.cap", "F",
                    "IMAP with no encryption offered at all",
                    "Cleartext LOGIN on port 143, and STARTTLS was never advertised. Two "
                            + "non-email conversations share the file and are correctly excluded."),
            new DemoCapture("pop-ssl.pcapng", "C",
                    "POP3 STARTTLS, undone by its certificate",
                    "A clean TLS 1.2 upgrade with forward secrecy and AES-256-GCM — a perfect "
                            + "100 on cryptography, capped to C by a self-signed certificate."),
            new DemoCapture("smtp-ssl.pcapng", "C",
                    "SMTP STARTTLS with a dated cipher",
                    "Encrypted, but negotiated a CBC suite that is no longer IANA-recommended, "
                            + "and the certificate is self-signed."),
            new DemoCapture("synthetic-imaps-tls13.pcap", "A+",
                    "IMAPS done correctly",
                    "TLS 1.3 with X25519 and AES-256-GCM on port 993. Nothing to fix. The "
                            + "certificate is encrypted by TLS 1.3, so the rules abstain and "
                            + "say so rather than guessing."));

    /** The demo set, minus anything not actually present on disk. */
    public List<DemoCapture> demoCaptures() {
        Path dir = properties.resolvedDemoDir();
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        return DEMOS.stream()
                .filter(d -> Files.isRegularFile(dir.resolve(d.name())))
                .toList();
    }

    public synchronized Capture analyse(Long captureId) {
        Capture capture = jobs.claim(captureId);
        if (capture == null) return captures.findById(captureId).orElseThrow();
        JsonNode output = null;
        String failure = null;
        Path historyFile = null;
        try {
            String path = capture.getStoragePath();
            if (path == null || !Files.exists(Path.of(path))) throw new IllegalStateException("Uploaded evidence is no longer on disk");
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var prior = mapper.createArrayNode();
            if (capture.getInvestigationId() != null) {
                for (Capture old : captures.findByInvestigationIdOrderByIdDesc(capture.getInvestigationId())) {
                    if (!old.getId().equals(captureId) && old.getStatus() == Capture.Status.COMPLETED && old.getReportJson() != null)
                        prior.add(mapper.readTree(old.getReportJson()));
                }
            }
            historyFile = Files.createTempFile("ms-history-", ".json");
            Files.writeString(historyFile, prior.toString());
            output = engine.analyse(Path.of(path), historyFile, stage -> jobs.progress(captureId, stage), () -> jobs.cancelled(captureId));
            ((com.fasterxml.jackson.databind.node.ObjectNode) output.path("capture")).put("filename", capture.getFilename());
            if (!capture.getSha256().equals(output.path("capture").path("sha256").asText()))
                throw new IllegalStateException("Evidence hash changed since upload; analysis rejected");
        } catch (Exception e) {
            failure = trim(e.getMessage(), 3900);
        } finally {
            if (historyFile != null) try { Files.deleteIfExists(historyFile); } catch (IOException ignored) { }
        }
        final JsonNode report = output;
        final String error = failure;
        return transactions.execute(tx -> {
            Capture c = captures.lockById(captureId).orElseThrow();
            if (c.getStatus() == Capture.Status.CANCELLED) return c;
            if (error != null || report == null) {
                c.setStatus(Capture.Status.FAILED); c.setStage("FAILED"); c.setErrorMessage(error);
            } else {
                apply(c, report); c.setStatus(Capture.Status.COMPLETED); c.setStage("COMPLETED");
                c.setAnalysedAt(Instant.now());
            }
            return captures.save(c);
        });
    }

    // ------------------------------------------------------------------
    // JSON -> entities
    // ------------------------------------------------------------------

    private void apply(Capture capture, JsonNode report) {
        capture.setReportJson(report.toString());

        JsonNode cap = report.path("capture");
        capture.setFormat(text(cap, "format"));
        capture.setPacketCount(intOrNull(cap, "packet_count"));
        capture.setCapturedAt(instant(text(cap, "first_packet_time")));
        if (capture.getSha256() == null) {
            capture.setSha256(text(cap, "sha256"));
        }

        capture.setOverallGrade(text(report, "overall_grade"));
        capture.setOverallScore(doubleOrNull(report, "overall_score"));

        JsonNode counts = report.path("counts");
        capture.setCriticalCount(intOrNull(counts, "critical"));
        capture.setHighCount(intOrNull(counts, "high"));
        capture.setMediumCount(intOrNull(counts, "medium"));
        capture.setLowCount(intOrNull(counts, "low"));
        capture.setSessionCount(intOrNull(counts, "sessions"));
        capture.setAssetCount(intOrNull(counts, "assets"));
        capture.setCredentialsExposed(intOrNull(counts, "credentials_exposed"));

        capture.getSessions().clear();
        capture.getAssets().clear();

        for (JsonNode s : report.path("sessions")) {
            capture.getSessions().add(toSession(capture, s));
        }
        for (JsonNode a : report.path("assets")) {
            capture.getAssets().add(toAsset(capture, a));
        }
    }

    private MailSession toSession(Capture capture, JsonNode s) {
        MailSession m = new MailSession();
        m.setCapture(capture);
        m.setSessionKey(text(s, "session_id"));
        m.setStreamIndex(s.path("tcp_stream").asInt());
        m.setFirstFrame(s.path("first_frame").asInt());
        m.setLastFrame(s.path("last_frame").asInt());
        m.setProtocol(text(s, "protocol"));
        m.setRole(text(s, "role"));
        m.setTlsMode(text(s, "tls_mode"));

        m.setClientIp(text(s.path("client"), "ip"));
        m.setClientPort(s.path("client").path("port").asInt());
        m.setServerIp(text(s.path("server"), "ip"));
        m.setServerPort(s.path("server").path("port").asInt());
        m.setServerName(text(s, "server_name"));

        m.setTlsVersion(text(s, "tls_version"));
        m.setCipherSuite(text(s, "cipher_suite"));
        m.setKeyExchange(text(s, "kex"));
        m.setKeyExchangeBits(intOrNull(s, "kex_bits"));
        m.setForwardSecrecy(boolOrNull(s, "forward_secrecy"));
        m.setJa3(text(s, "ja3"));
        m.setJa4(text(s, "ja4"));

        m.setCertVisibility(text(s, "cert_visibility"));
        JsonNode chain = s.path("chain");
        if (chain.isArray() && chain.size() > 0) {
            JsonNode leaf = chain.get(0);
            m.setCertSubject(trim(text(leaf, "subject"), 250));
            m.setCertIssuer(trim(text(leaf, "issuer"), 250));
            m.setCertSelfSigned(boolOrNull(leaf, "self_signed"));
            m.setCertExpiredAtCapture(boolOrNull(leaf, "expired_at_capture"));
        }
        m.setChainValid(boolOrNull(s, "chain_valid"));

        m.setStarttlsOffered(boolOrNull(s, "starttls_offered"));
        m.setStarttlsRequested(boolOrNull(s, "starttls_requested"));
        m.setStarttlsAccepted(boolOrNull(s, "starttls_accepted"));
        m.setCapabilityMangled(boolOrNull(s, "capability_mangled"));

        JsonNode auth = s.path("cleartext_auth");
        m.setCleartextAuth(!auth.isMissingNode() && !auth.isNull());
        if (Boolean.TRUE.equals(m.getCleartextAuth())) {
            // Already redacted by the engine; the secret itself is never present.
            m.setExposedUsername(trim(text(auth, "username"), 250));
        }

        JsonNode grade = s.path("grade");
        m.setGrade(text(grade, "letter"));
        m.setRawScore(doubleOrNull(grade, "raw_score"));
        m.setCappedBy(text(grade, "capped_by"));
        m.setTrusted(boolOrNull(grade, "trusted"));
        m.setConfidence(text(s, "confidence"));

        JsonNode ml = s.path("ml");
        if (!ml.isMissingNode() && !ml.isNull()) {
            m.setMlRiskClass(text(ml, "risk_class"));
            m.setMlRiskScore(doubleOrNull(ml, "risk_score"));
            m.setMlAnomaly(boolOrNull(ml, "anomaly"));
            m.setMlExplanation(trim(text(ml, "explanation"), 1990));
        }

        for (JsonNode f : s.path("findings")) {
            Finding finding = new Finding();
            finding.setSession(m);
            finding.setRuleId(text(f, "rule_id"));
            finding.setSeverity(text(f, "severity"));
            finding.setTitle(trim(text(f, "title"), 250));
            finding.setStandard(trim(text(f, "standard"), 500));
            finding.setRemediation(trim(text(f, "remediation"), 1990));
            finding.setDetail(trim(text(f, "detail"), 1990));
            finding.setCapGrade(text(f, "cap_grade"));
            StringJoiner frames = new StringJoiner(",");
            for (JsonNode fr : f.path("evidence").path("frames")) {
                frames.add(fr.asText());
            }
            finding.setEvidenceFrames(trim(frames.toString(), 500));
            m.getFindings().add(finding);
        }
        return m;
    }

    private Asset toAsset(Capture capture, JsonNode a) {
        Asset asset = new Asset();
        asset.setCapture(capture);
        asset.setAssetKey(trim(text(a, "key"), 250));
        asset.setHost(trim(text(a, "host"), 250));
        asset.setPort(a.path("port").asInt());
        asset.setProtocol(text(a, "protocol"));
        asset.setRole(text(a, "role"));
        asset.setSessionCount(a.path("session_count").asInt());
        asset.setDistinctClients(a.path("distinct_clients").asInt());
        asset.setBestTls(text(a, "best_tls"));
        asset.setWorstTls(text(a, "worst_tls"));
        asset.setVersionSpread(boolOrNull(a, "version_spread"));
        asset.setCredentialsExposed(boolOrNull(a, "credentials_exposed"));
        asset.setExposureScore(doubleOrNull(a, "exposure_score"));
        asset.setMlRisk(doubleOrNull(a, "ml_risk"));

        JsonNode grade = a.path("grade");
        asset.setGrade(text(grade, "letter"));
        asset.setRawScore(doubleOrNull(grade, "raw_score"));
        asset.setCappedBy(text(grade, "capped_by"));
        asset.setTrusted(boolOrNull(grade, "trusted"));
        return asset;
    }

    // ------------------------------------------------------------------
    // defensive JSON helpers
    // ------------------------------------------------------------------

    private static String text(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asText();
    }

    private static Integer intOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() || !v.isNumber() ? null : v.asInt();
    }

    private static Double doubleOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() || !v.isNumber() ? null : v.asDouble();
    }

    private static Boolean boolOrNull(JsonNode node, String field) {
        JsonNode v = node.path(field);
        return v.isMissingNode() || v.isNull() ? null : v.asBoolean();
    }

    private static Instant instant(String iso) {
        if (iso == null || iso.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(iso).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String trim(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static String sanitise(String name) {
        if (name == null || name.isBlank()) {
            return "capture.pcap";
        }
        String base = name.replace('\\', '/');
        base = base.substring(base.lastIndexOf('/') + 1);
        return base.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static boolean looksLikeCapture(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.endsWith(".pcap") || n.endsWith(".pcapng") || n.endsWith(".cap")
                || n.endsWith(".pcap.gz") || n.endsWith(".pcapng.gz");
    }
}
