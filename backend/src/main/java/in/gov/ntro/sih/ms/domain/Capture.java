package in.gov.ntro.sih.ms.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * One uploaded capture file and the analysis produced from it.
 *
 * <p>The full engine JSON is retained verbatim in {@code reportJson} so the
 * exact evidence can be re-served or re-examined later, while the columns
 * beside it exist so the dashboard can sort and filter in SQL rather than by
 * parsing documents.
 */
@Entity
@Table(name = "capture", indexes = {
        @Index(name = "idx_capture_sha256", columnList = "sha256"),
        @Index(name = "idx_capture_status", columnList = "status")
})
public class Capture {

    public enum Status { PENDING, RUNNING, COMPLETED, FAILED, CANCELLED }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 512)
    private String filename;

    /** Chain of custody: taken on upload, before anything touches the bytes. */
    @Column(length = 64)
    private String sha256;

    private long sizeBytes;

    @Column(length = 32)
    private String format;

    /** Where the uploaded bytes live on disk. Persisted so analysis survives a restart. */
    @Column(length = 1024)
    private String storagePath;

    private Integer packetCount;

    private Instant capturedAt;
    private Instant uploadedAt = Instant.now();
    private Instant analysedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Status status = Status.PENDING;

    @Column(length = 4000)
    private String errorMessage;

    @Column(length = 4)
    private String overallGrade;

    private Double overallScore;

    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Integer sessionCount;
    private Integer assetCount;
    private Integer credentialsExposed;

    /**
     * The engine's JSON document, stored verbatim.
     *
     * <p>Deliberately not {@code @Lob}. On PostgreSQL that annotation maps a
     * String to a large-object OID reference rather than to text, which needs
     * separate lifecycle management and does not behave like a column. On H2 in
     * PostgreSQL mode it makes Hibernate expect CLOB while the migration
     * declares TEXT, and schema validation fails outright at startup. A plain
     * String against a TEXT column is what both databases actually want.
     */
    @Column(name = "report_json", columnDefinition = "TEXT")
    private String reportJson;

    @OneToMany(mappedBy = "capture", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<MailSession> sessions = new ArrayList<>();

    @OneToMany(mappedBy = "capture", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Asset> assets = new ArrayList<>();

    private Long investigationId;
    private Long sourceCaptureId;
    @Column(length=64) private String stage = "QUEUED";
    private Instant startedAt;
    public Long getInvestigationId() { return investigationId; }
    public void setInvestigationId(Long value) { investigationId = value; }
    public Long getSourceCaptureId() { return sourceCaptureId; }
    public void setSourceCaptureId(Long value) { sourceCaptureId = value; }
    public String getStage() { return stage; }
    public void setStage(String value) { stage = value; }
    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant value) { startedAt = value; }

    // ---- accessors -------------------------------------------------------

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }

    public String getSha256() { return sha256; }
    public void setSha256(String sha256) { this.sha256 = sha256; }

    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }

    public String getStoragePath() { return storagePath; }
    public void setStoragePath(String storagePath) { this.storagePath = storagePath; }

    public String getFormat() { return format; }
    public void setFormat(String format) { this.format = format; }

    public Integer getPacketCount() { return packetCount; }
    public void setPacketCount(Integer packetCount) { this.packetCount = packetCount; }

    public Instant getCapturedAt() { return capturedAt; }
    public void setCapturedAt(Instant capturedAt) { this.capturedAt = capturedAt; }

    public Instant getUploadedAt() { return uploadedAt; }
    public void setUploadedAt(Instant uploadedAt) { this.uploadedAt = uploadedAt; }

    public Instant getAnalysedAt() { return analysedAt; }
    public void setAnalysedAt(Instant analysedAt) { this.analysedAt = analysedAt; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public String getOverallGrade() { return overallGrade; }
    public void setOverallGrade(String overallGrade) { this.overallGrade = overallGrade; }

    public Double getOverallScore() { return overallScore; }
    public void setOverallScore(Double overallScore) { this.overallScore = overallScore; }

    public Integer getCriticalCount() { return criticalCount; }
    public void setCriticalCount(Integer criticalCount) { this.criticalCount = criticalCount; }

    public Integer getHighCount() { return highCount; }
    public void setHighCount(Integer highCount) { this.highCount = highCount; }

    public Integer getMediumCount() { return mediumCount; }
    public void setMediumCount(Integer mediumCount) { this.mediumCount = mediumCount; }

    public Integer getLowCount() { return lowCount; }
    public void setLowCount(Integer lowCount) { this.lowCount = lowCount; }

    public Integer getSessionCount() { return sessionCount; }
    public void setSessionCount(Integer sessionCount) { this.sessionCount = sessionCount; }

    public Integer getAssetCount() { return assetCount; }
    public void setAssetCount(Integer assetCount) { this.assetCount = assetCount; }

    public Integer getCredentialsExposed() { return credentialsExposed; }
    public void setCredentialsExposed(Integer credentialsExposed) { this.credentialsExposed = credentialsExposed; }

    public String getReportJson() { return reportJson; }
    public void setReportJson(String reportJson) { this.reportJson = reportJson; }

    public List<MailSession> getSessions() { return sessions; }
    public void setSessions(List<MailSession> sessions) { this.sessions = sessions; }

    public List<Asset> getAssets() { return assets; }
    public void setAssets(List<Asset> assets) { this.assets = assets; }
}
