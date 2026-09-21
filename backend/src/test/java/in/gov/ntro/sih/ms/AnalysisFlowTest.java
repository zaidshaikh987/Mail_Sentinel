package in.gov.ntro.sih.ms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import in.gov.ntro.sih.ms.engine.EngineClient;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * End-to-end flow through the API: upload a real capture, run the real engine,
 * persist, and read it back.
 *
 * <p>This is deliberately not mocked. The one thing worth testing at this layer
 * is that the Java and Python halves actually agree about the JSON contract
 * between them, and a mocked engine would test the opposite.
 *
 * <p>When the Python engine is not installed the engine-dependent tests skip
 * rather than fail — a machine without it can still run the rest of the suite.
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("capture upload → analysis → retrieval")
class AnalysisFlowTest {

    @Autowired private WebApplicationContext context;
    @Autowired private CaptureRepository captures;
    @Autowired private EngineClient engine;

    private MockMvc mvc;

    /** demo-pcaps/ sits two levels up from backend/ in the repository. */
    private static Path capture(String name) {
        return Paths.get("..", "demo-pcaps", name).toAbsolutePath().normalize();
    }

    /**
     * Whether the Python engine can actually run here.
     *
     * <p>Engine-dependent tests skip rather than fail when it cannot, so a
     * machine without the engine installed can still run the rest of the suite.
     * The probe imports the analysis pipeline, not just the package, so a
     * missing dependency is detected here instead of surfacing as a mysterious
     * failed capture three assertions later.
     */
    private String engineUnavailableReason() {
        EngineClient.EngineStatus status = engine.probe();
        return status.ready() ? null
                : "python engine not runnable: " + status.error();
    }

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).build();
        captures.deleteAll();
    }

    @Test
    @DisplayName("health reports whether the analysis engine can be reached")
    void healthEndpoint() throws Exception {
        mvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").exists())
                .andExpect(jsonPath("$.engine").exists());
    }

    @Test
    @DisplayName("a non-capture upload is rejected with an explanation")
    void rejectsNonCapture() throws Exception {
        MockMultipartFile bad = new MockMultipartFile(
                "file", "notes.txt", MediaType.TEXT_PLAIN_VALUE, "hello".getBytes());

        mvc.perform(multipart("/api/captures").file(bad))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString(".pcap")));
    }

    @Test
    @DisplayName("uploading smtp.pcap yields grade F with credentials exposed")
    void analysesCleartextSmtp() throws Exception {
        assumeThat(engineUnavailableReason()).as("engine availability").isNull();
        Path pcap = capture("smtp.pcap");
        assumeThat(Files.exists(pcap)).as("demo capture present").isTrue();

        MockMultipartFile file = new MockMultipartFile(
                "file", "smtp.pcap", "application/octet-stream", Files.readAllBytes(pcap));

        String body = mvc.perform(multipart("/api/captures/sync").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.overallGrade").value("F"))
                .andExpect(jsonPath("$.counts.credentialsExposed").value(1))
                .andReturn().getResponse().getContentAsString();

        assertThat(body).contains("sha256");
    }

    @Test
    @DisplayName("the SHA-256 recorded on upload is the hash of the file itself")
    void recordsChainOfCustodyHash() throws Exception {
        assumeThat(engineUnavailableReason()).as("engine availability").isNull();
        Path pcap = capture("pop-ssl.pcapng");
        assumeThat(Files.exists(pcap)).as("demo capture present").isTrue();

        byte[] bytes = Files.readAllBytes(pcap);
        String expected = java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(bytes));

        MockMultipartFile file =
                new MockMultipartFile("file", "pop-ssl.pcapng", "application/octet-stream", bytes);

        mvc.perform(multipart("/api/captures/sync").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sha256").value(expected));
    }

    @Test
    @DisplayName("sessions, findings and assets are persisted and readable")
    void persistsTheAnalysis() throws Exception {
        assumeThat(engineUnavailableReason()).as("engine availability").isNull();
        Path pcap = capture("pop-ssl.pcapng");
        assumeThat(Files.exists(pcap)).as("demo capture present").isTrue();

        MockMultipartFile file = new MockMultipartFile(
                "file", "pop-ssl.pcapng", "application/octet-stream", Files.readAllBytes(pcap));

        String created = mvc.perform(multipart("/api/captures/sync").file(file))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        long id = com.jayway.jsonpath.JsonPath.parse(created).read("$.id", Integer.class);

        // The POP3 capture upgrades cleanly to TLS 1.2 but presents a
        // self-signed certificate, so it caps at C.
        mvc.perform(get("/api/captures/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessions[0].protocol").value("pop3"))
                .andExpect(jsonPath("$.sessions[0].tlsVersion").value("1.2"))
                .andExpect(jsonPath("$.sessions[0].grade").value("C"))
                .andExpect(jsonPath("$.sessions[0].cappedBy").value("SMS-CERT-003"))
                .andExpect(jsonPath("$.assets[0].host").exists());

        mvc.perform(get("/api/captures/{id}/sessions", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].certVisibility").value("observed"));

        // The verbatim engine document must survive the round trip intact.
        mvc.perform(get("/api/captures/{id}/report.json", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.schema_version").exists())
                .andExpect(jsonPath("$.sessions[0].findings").isArray());
    }

    @Test
    @DisplayName("a certificate valid when captured is not reported as expired")
    void doesNotReportHistoricalCertificatesAsExpired() throws Exception {
        assumeThat(engineUnavailableReason()).as("engine availability").isNull();
        Path pcap = capture("smtp-ssl.pcapng");
        assumeThat(Files.exists(pcap)).as("demo capture present").isTrue();

        MockMultipartFile file = new MockMultipartFile(
                "file", "smtp-ssl.pcapng", "application/octet-stream", Files.readAllBytes(pcap));

        String created = mvc.perform(multipart("/api/captures/sync").file(file))
                .andReturn().getResponse().getContentAsString();
        long id = com.jayway.jsonpath.JsonPath.parse(created).read("$.id", Integer.class);

        // Recorded in 2015 with a certificate that has since lapsed. Judged
        // against the capture clock it was valid at the time, and no
        // SMS-CERT-001 may appear.
        mvc.perform(get("/api/captures/{id}/sessions", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].certExpiredAtCapture").value(false));

        mvc.perform(get("/api/captures/{id}/report.json", id))
                .andExpect(jsonPath(
                        "$.sessions[0].findings[?(@.rule_id == 'SMS-CERT-001')]").isEmpty());
    }

    @Test
    @DisplayName("an unknown capture id is a 404 with a readable message")
    void unknownCaptureIsNotFound() throws Exception {
        mvc.perform(get("/api/captures/{id}", 999999))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").exists());
    }
}
