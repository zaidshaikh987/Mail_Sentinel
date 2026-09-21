package in.gov.ntro.sih.ms.domain;
import jakarta.persistence.*;
import java.time.Instant;
@Entity
public class Investigation {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @Column(nullable=false, length=160) private String name;
    @Column(nullable=false) private Instant createdAt = Instant.now();
    public Long getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public Instant getCreatedAt() { return createdAt; }
}
