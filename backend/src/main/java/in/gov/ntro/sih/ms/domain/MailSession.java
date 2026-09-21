package in.gov.ntro.sih.ms.domain;

import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;

/** One reconstructed email conversation, with its deterministic grade and the model's advisory view. */
@Entity
@Table(name = "mail_session", indexes = {
        @Index(name = "idx_session_capture", columnList = "capture_id"),
        @Index(name = "idx_session_grade", columnList = "grade")
})
public class MailSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "capture_id", nullable = false)
    private Capture capture;

    @Column(length = 64)  private String sessionKey;      // engine session_id
    private int streamIndex;
    private int firstFrame;
    private int lastFrame;

    @Column(length = 16)  private String protocol;        // smtp | imap | pop3
    @Column(length = 32)  private String role;            // submission_access | mta_relay
    @Column(length = 16)  private String tlsMode;         // implicit | starttls | cleartext

    @Column(length = 64)  private String clientIp;
    private int clientPort;
    @Column(length = 64)  private String serverIp;
    private int serverPort;
    @Column(length = 255) private String serverName;

    @Column(length = 16)  private String tlsVersion;
    @Column(length = 128) private String cipherSuite;
    @Column(length = 16)  private String keyExchange;
    private Integer keyExchangeBits;
    private Boolean forwardSecrecy;

    @Column(length = 32)  private String certVisibility;
    @Column(length = 255) private String certSubject;
    @Column(length = 255) private String certIssuer;
    private Boolean certSelfSigned;
    private Boolean certExpiredAtCapture;
    private Boolean chainValid;

    private Boolean starttlsOffered;
    private Boolean starttlsRequested;
    private Boolean starttlsAccepted;
    private Boolean capabilityMangled;
    private Boolean cleartextAuth;
    @Column(length = 255) private String exposedUsername;   // already redacted by the engine

    @Column(length = 4)   private String grade;
    private Double rawScore;
    @Column(length = 32)  private String cappedBy;
    private Boolean trusted;
    @Column(length = 16)  private String confidence;

    @Column(length = 16)  private String mlRiskClass;
    private Double mlRiskScore;
    private Boolean mlAnomaly;
    @Column(length = 2000) private String mlExplanation;

    @Column(length = 64)  private String ja3;
    @Column(length = 64)  private String ja4;

    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Finding> findings = new ArrayList<>();

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public Capture getCapture() { return capture; }
    public void setCapture(Capture capture) { this.capture = capture; }
    public String getSessionKey() { return sessionKey; }
    public void setSessionKey(String v) { this.sessionKey = v; }
    public int getStreamIndex() { return streamIndex; }
    public void setStreamIndex(int v) { this.streamIndex = v; }
    public int getFirstFrame() { return firstFrame; }
    public void setFirstFrame(int v) { this.firstFrame = v; }
    public int getLastFrame() { return lastFrame; }
    public void setLastFrame(int v) { this.lastFrame = v; }
    public String getProtocol() { return protocol; }
    public void setProtocol(String v) { this.protocol = v; }
    public String getRole() { return role; }
    public void setRole(String v) { this.role = v; }
    public String getTlsMode() { return tlsMode; }
    public void setTlsMode(String v) { this.tlsMode = v; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String v) { this.clientIp = v; }
    public int getClientPort() { return clientPort; }
    public void setClientPort(int v) { this.clientPort = v; }
    public String getServerIp() { return serverIp; }
    public void setServerIp(String v) { this.serverIp = v; }
    public int getServerPort() { return serverPort; }
    public void setServerPort(int v) { this.serverPort = v; }
    public String getServerName() { return serverName; }
    public void setServerName(String v) { this.serverName = v; }
    public String getTlsVersion() { return tlsVersion; }
    public void setTlsVersion(String v) { this.tlsVersion = v; }
    public String getCipherSuite() { return cipherSuite; }
    public void setCipherSuite(String v) { this.cipherSuite = v; }
    public String getKeyExchange() { return keyExchange; }
    public void setKeyExchange(String v) { this.keyExchange = v; }
    public Integer getKeyExchangeBits() { return keyExchangeBits; }
    public void setKeyExchangeBits(Integer v) { this.keyExchangeBits = v; }
    public Boolean getForwardSecrecy() { return forwardSecrecy; }
    public void setForwardSecrecy(Boolean v) { this.forwardSecrecy = v; }
    public String getCertVisibility() { return certVisibility; }
    public void setCertVisibility(String v) { this.certVisibility = v; }
    public String getCertSubject() { return certSubject; }
    public void setCertSubject(String v) { this.certSubject = v; }
    public String getCertIssuer() { return certIssuer; }
    public void setCertIssuer(String v) { this.certIssuer = v; }
    public Boolean getCertSelfSigned() { return certSelfSigned; }
    public void setCertSelfSigned(Boolean v) { this.certSelfSigned = v; }
    public Boolean getCertExpiredAtCapture() { return certExpiredAtCapture; }
    public void setCertExpiredAtCapture(Boolean v) { this.certExpiredAtCapture = v; }
    public Boolean getChainValid() { return chainValid; }
    public void setChainValid(Boolean v) { this.chainValid = v; }
    public Boolean getStarttlsOffered() { return starttlsOffered; }
    public void setStarttlsOffered(Boolean v) { this.starttlsOffered = v; }
    public Boolean getStarttlsRequested() { return starttlsRequested; }
    public void setStarttlsRequested(Boolean v) { this.starttlsRequested = v; }
    public Boolean getStarttlsAccepted() { return starttlsAccepted; }
    public void setStarttlsAccepted(Boolean v) { this.starttlsAccepted = v; }
    public Boolean getCapabilityMangled() { return capabilityMangled; }
    public void setCapabilityMangled(Boolean v) { this.capabilityMangled = v; }
    public Boolean getCleartextAuth() { return cleartextAuth; }
    public void setCleartextAuth(Boolean v) { this.cleartextAuth = v; }
    public String getExposedUsername() { return exposedUsername; }
    public void setExposedUsername(String v) { this.exposedUsername = v; }
    public String getGrade() { return grade; }
    public void setGrade(String v) { this.grade = v; }
    public Double getRawScore() { return rawScore; }
    public void setRawScore(Double v) { this.rawScore = v; }
    public String getCappedBy() { return cappedBy; }
    public void setCappedBy(String v) { this.cappedBy = v; }
    public Boolean getTrusted() { return trusted; }
    public void setTrusted(Boolean v) { this.trusted = v; }
    public String getConfidence() { return confidence; }
    public void setConfidence(String v) { this.confidence = v; }
    public String getMlRiskClass() { return mlRiskClass; }
    public void setMlRiskClass(String v) { this.mlRiskClass = v; }
    public Double getMlRiskScore() { return mlRiskScore; }
    public void setMlRiskScore(Double v) { this.mlRiskScore = v; }
    public Boolean getMlAnomaly() { return mlAnomaly; }
    public void setMlAnomaly(Boolean v) { this.mlAnomaly = v; }
    public String getMlExplanation() { return mlExplanation; }
    public void setMlExplanation(String v) { this.mlExplanation = v; }
    public String getJa3() { return ja3; }
    public void setJa3(String v) { this.ja3 = v; }
    public String getJa4() { return ja4; }
    public void setJa4(String v) { this.ja4 = v; }
    public List<Finding> getFindings() { return findings; }
    public void setFindings(List<Finding> v) { this.findings = v; }
}
