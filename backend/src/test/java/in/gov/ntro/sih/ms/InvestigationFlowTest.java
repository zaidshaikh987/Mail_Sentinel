package in.gov.ntro.sih.ms;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import in.gov.ntro.sih.ms.domain.Capture;
import in.gov.ntro.sih.ms.repo.CaptureRepository;
import in.gov.ntro.sih.ms.service.AnalysisService;
import in.gov.ntro.sih.ms.service.JobState;
import java.nio.file.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.mock.web.MockMultipartFile;

@SpringBootTest @ActiveProfiles("test")
class InvestigationFlowTest {
    @Autowired WebApplicationContext context;
    @Autowired CaptureRepository captures;
    @Autowired AnalysisService analysis;
    @Autowired JobState jobs;
    MockMvc mvc;
    ObjectMapper mapper = new ObjectMapper();
    @BeforeEach void setup() { mvc = MockMvcBuilders.webAppContextSetup(context).build(); captures.deleteAll(); }
    long investigation() throws Exception {
        String body = mvc.perform(post("/api/investigations").contentType("application/json").content("{\"name\":\"Lab review\"}"))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(body).path("id").asLong();
    }
    long upload(long id, String name) throws Exception {
        var file = new MockMultipartFile("file", name, "application/octet-stream", Files.readAllBytes(Path.of("../demo-pcaps", name)));
        String body = mvc.perform(multipart("/api/captures").file(file).param("investigationId", ""+id))
            .andExpect(status().isAccepted()).andExpect(jsonPath("$.status").value("PENDING")).andReturn().getResponse().getContentAsString();
        return mapper.readTree(body).path("id").asLong();
    }
    @Test void jobLifecyclePreservesEvidenceAndReports() throws Exception {
        long i = investigation(), run = upload(i, "smtp.pcap");
        assertThat(captures.findById(run).orElseThrow().getInvestigationId()).isEqualTo(i);
        mvc.perform(post("/api/captures/"+run+"/cancel")).andExpect(jsonPath("$.status").value("CANCELLED"));
        String retry = mvc.perform(post("/api/captures/"+run+"/retry")).andExpect(status().isOk()).andExpect(jsonPath("$.sourceCaptureId").value(run)).andReturn().getResponse().getContentAsString();
        long next = mapper.readTree(retry).path("id").asLong();
        assertThat(next).isNotEqualTo(run);
        assertThat(analysis.analyse(next).getStatus()).isEqualTo(Capture.Status.COMPLETED);
        mvc.perform(get("/api/captures/"+next)).andExpect(jsonPath("$.report.provenance.rules_sha256").exists())
            .andExpect(jsonPath("$.report.coverage.assessed_checks").isNumber())
            .andExpect(jsonPath("$.report.capture.filename").value("smtp.pcap"));
        assertThat(captures.findById(run).orElseThrow().getStatus()).isEqualTo(Capture.Status.CANCELLED);
    }
    @Test void comparisonIsScopedAndNeverClaimsMissingFindingFixed() throws Exception {
        long i = investigation(), a = upload(i, "smtp.pcap"), b = upload(i, "synthetic-imaps-tls13.pcap");
        analysis.analyse(a); analysis.analyse(b);
        String body = mvc.perform(get("/api/investigations/"+i+"/compare").param("before", ""+a).param("after", ""+b))
            .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(body).contains("not_observed_in_later_capture").doesNotContain("\"state\":\"resolved\"");
        long other = investigation();
        mvc.perform(get("/api/investigations/"+other+"/compare").param("before", ""+a).param("after", ""+b)).andExpect(status().isBadRequest());
        var finding = mapper.readTree(body).path("findings").get(0);
        mvc.perform(put("/api/investigations/"+i+"/remediation").contentType("application/json")
            .content(mapper.writeValueAsString(java.util.Map.of("key",finding.path("key").asText(),"status","in_progress","note","Checking configuration"))))
            .andExpect(status().isOk());
        mvc.perform(get("/api/investigations/"+i)).andExpect(jsonPath("$.remediation[0].status").value("in_progress"));
    }
    @Test void interruptedRunsRemainAuditable() throws Exception {
        long i = investigation(), id = upload(i,"smtp.pcap");
        jobs.claim(id); jobs.progress(id,"REASSEMBLING");
        mvc.perform(get("/api/captures/"+id)).andExpect(jsonPath("$.stage").value("REASSEMBLING"));
        jobs.recoverInterrupted();
        assertThat(captures.findById(id).orElseThrow().getStage()).isEqualTo("INTERRUPTED");
    }
    @Test void invalidInvestigationRollsBackQueuedRun() throws Exception {
        mvc.perform(multipart("/api/captures").file(new MockMultipartFile("file","smtp.pcap","application/octet-stream",Files.readAllBytes(Path.of("../demo-pcaps/smtp.pcap"))))
            .param("investigationId","999999")).andExpect(status().isBadRequest());
        assertThat(captures.count()).isZero();
    }
}
