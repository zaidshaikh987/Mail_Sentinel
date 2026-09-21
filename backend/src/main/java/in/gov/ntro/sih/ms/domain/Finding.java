package in.gov.ntro.sih.ms.domain;

import jakarta.persistence.*;

/**
 * One rule verdict.
 *
 * <p>Every row carries the published clause it enforces and the frame numbers
 * it was derived from, so a claim in the dashboard can always be traced back to
 * packets in the evidence file.
 */
@Entity
@Table(name = "finding", indexes = {
        @Index(name = "idx_finding_session", columnList = "session_id"),
        @Index(name = "idx_finding_rule", columnList = "rule_id"),
        @Index(name = "idx_finding_severity", columnList = "severity")
})
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false)
    private MailSession session;

    @Column(name = "rule_id", nullable = false, length = 32)
    private String ruleId;

    @Column(nullable = false, length = 16)
    private String severity;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(length = 512)
    private String standard;

    @Column(length = 2000)
    private String remediation;

    @Column(length = 2000)
    private String detail;

    @Column(length = 4)
    private String capGrade;

    /** Comma-separated frame numbers backing this finding. */
    @Column(length = 512)
    private String evidenceFrames;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public MailSession getSession() { return session; }
    public void setSession(MailSession v) { this.session = v; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String v) { this.ruleId = v; }
    public String getSeverity() { return severity; }
    public void setSeverity(String v) { this.severity = v; }
    public String getTitle() { return title; }
    public void setTitle(String v) { this.title = v; }
    public String getStandard() { return standard; }
    public void setStandard(String v) { this.standard = v; }
    public String getRemediation() { return remediation; }
    public void setRemediation(String v) { this.remediation = v; }
    public String getDetail() { return detail; }
    public void setDetail(String v) { this.detail = v; }
    public String getCapGrade() { return capGrade; }
    public void setCapGrade(String v) { this.capGrade = v; }
    public String getEvidenceFrames() { return evidenceFrames; }
    public void setEvidenceFrames(String v) { this.evidenceFrames = v; }
}
