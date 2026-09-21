package in.gov.ntro.sih.ms.domain;

import jakarta.persistence.*;

/**
 * A mail server observed in the capture — the unit an administrator acts on.
 *
 * <p>Sessions are evidence; assets are the fix queue. {@code exposureScore}
 * ranks them by risk multiplied by reach, so two servers that both grade F are
 * separated by how much traffic and how many credentials each actually carried.
 */
@Entity
@Table(name = "asset", indexes = {
        @Index(name = "idx_asset_capture", columnList = "capture_id"),
        @Index(name = "idx_asset_exposure", columnList = "exposure_score")
})
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "capture_id", nullable = false)
    private Capture capture;

    @Column(nullable = false, length = 255) private String assetKey;
    @Column(nullable = false, length = 255) private String host;
    private int port;
    @Column(length = 16) private String protocol;
    @Column(length = 32) private String role;

    @Column(length = 4)  private String grade;
    private Double rawScore;
    @Column(length = 32) private String cappedBy;
    private Boolean trusted;

    private int sessionCount;
    private int distinctClients;
    @Column(length = 16) private String bestTls;
    @Column(length = 16) private String worstTls;
    private Boolean versionSpread;
    private Boolean credentialsExposed;

    @Column(name = "exposure_score")
    private Double exposureScore;

    private Double mlRisk;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Capture getCapture() { return capture; }
    public void setCapture(Capture v) { this.capture = v; }
    public String getAssetKey() { return assetKey; }
    public void setAssetKey(String v) { this.assetKey = v; }
    public String getHost() { return host; }
    public void setHost(String v) { this.host = v; }
    public int getPort() { return port; }
    public void setPort(int v) { this.port = v; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String v) { this.protocol = v; }
    public String getRole() { return role; }
    public void setRole(String v) { this.role = v; }
    public String getGrade() { return grade; }
    public void setGrade(String v) { this.grade = v; }
    public Double getRawScore() { return rawScore; }
    public void setRawScore(Double v) { this.rawScore = v; }
    public String getCappedBy() { return cappedBy; }
    public void setCappedBy(String v) { this.cappedBy = v; }
    public Boolean getTrusted() { return trusted; }
    public void setTrusted(Boolean v) { this.trusted = v; }
    public int getSessionCount() { return sessionCount; }
    public void setSessionCount(int v) { this.sessionCount = v; }
    public int getDistinctClients() { return distinctClients; }
    public void setDistinctClients(int v) { this.distinctClients = v; }
    public String getBestTls() { return bestTls; }
    public void setBestTls(String v) { this.bestTls = v; }
    public String getWorstTls() { return worstTls; }
    public void setWorstTls(String v) { this.worstTls = v; }
    public Boolean getVersionSpread() { return versionSpread; }
    public void setVersionSpread(Boolean v) { this.versionSpread = v; }
    public Boolean getCredentialsExposed() { return credentialsExposed; }
    public void setCredentialsExposed(Boolean v) { this.credentialsExposed = v; }
    public Double getExposureScore() { return exposureScore; }
    public void setExposureScore(Double v) { this.exposureScore = v; }
    public Double getMlRisk() { return mlRisk; }
    public void setMlRisk(Double v) { this.mlRisk = v; }
}
