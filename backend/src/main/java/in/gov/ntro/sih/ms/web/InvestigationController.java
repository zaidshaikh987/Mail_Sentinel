package in.gov.ntro.sih.ms.web;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import in.gov.ntro.sih.ms.domain.*;
import in.gov.ntro.sih.ms.repo.*;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/investigations")
public class InvestigationController {
    private final InvestigationRepository investigations;
    private final CaptureRepository captures;
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper = new ObjectMapper();
    public InvestigationController(InvestigationRepository investigations, CaptureRepository captures, JdbcTemplate jdbc) {
        this.investigations = investigations; this.captures = captures; this.jdbc = jdbc;
    }
    @GetMapping public List<Investigation> list() { return investigations.findAll(); }
    @PostMapping public Investigation create(@RequestBody Map<String,String> body) {
        String name = body.getOrDefault("name", "").trim();
        if (name.isEmpty() || name.length() > 160) throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Use an investigation name of 1–160 characters");
        Investigation i = new Investigation(); i.setName(name); return investigations.save(i);
    }
    private Investigation require(Long id) { return investigations.findById(id).orElseThrow(() -> new IllegalArgumentException("Investigation not found")); }
    @GetMapping("/{id}")
    public Map<String,Object> detail(@PathVariable Long id) {
        Investigation i = require(id);
        var runs = captures.findByInvestigationIdOrderByIdDesc(id);
        List<Map<String,Object>> servers = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Capture c : runs) {
            if (c.getStatus() != Capture.Status.COMPLETED) continue;
            JsonNode report = report(c);
            for (JsonNode server : report.path("history").path("servers")) {
                // Keep observations rather than silently merging endpoint identities.
                String key = server.path("identity").asText();
                if (seen.add(key)) servers.add(Map.of("captureId", c.getId(), "observedAt", Objects.toString(c.getCapturedAt(), "unknown"), "assessment", server));
            }
        }
        return Map.of("investigation", i, "runs", runs.stream().map(CaptureController::summary).toList(), "servers", servers,
                "remediation", jdbc.queryForList("select finding_key, status, note, updated_at from remediation_status where investigation_id = ?", id));
    }
    @GetMapping("/{id}/compare")
    public Map<String,Object> compare(@PathVariable Long id, @RequestParam Long before, @RequestParam Long after) {
        require(id);
        if (before.equals(after)) throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Select two different analysis runs");
        Capture a = run(id, before), b = run(id, after);
        JsonNode left = report(a), right = report(b);
        var old = findings(left); var next = findings(right);
        Set<String> keys = new TreeSet<>(old.keySet()); keys.addAll(next.keySet());
        List<Map<String,Object>> changes = new ArrayList<>();
        for (String key : keys) {
            JsonNode f = next.containsKey(key) ? next.get(key) : old.get(key);
            String state = old.containsKey(key) ? next.containsKey(key) ? "still_observed" : "not_observed_in_later_capture" : "newly_observed";
            changes.add(Map.of("key", key, "state", state, "rule", f.path("rule_id").asText(), "title", f.path("title").asText(),
                    "severity", f.path("severity").asText(), "remediation", f.path("remediation").asText()));
        }
        List<Map<String,Object>> servers = new ArrayList<>();
        var oldServers = serverObservations(left); var newServers = serverObservations(right);
        Set<String> identities = new TreeSet<>(oldServers.keySet()); identities.addAll(newServers.keySet());
        for (String identity : identities) {
            var prev = oldServers.getOrDefault(identity, Map.of()); var curr = newServers.getOrDefault(identity, Map.of());
            servers.add(Map.of("identity", identity, "before", prev, "after", curr,
                    "match", prev.isEmpty() || curr.isEmpty() ? "not_matched" : identity.split("\\|", -1)[1].isEmpty() ? "provisional_endpoint_only" : "hostname_and_endpoint"));
        }
        List<String> caveats = new ArrayList<>();
        caveats.add("Missing findings mean not observed, not proven fixed. Endpoint-only matches are provisional. Changed addresses or names are not automatically merged.");
        if (Objects.equals(a.getSha256(), b.getSha256())) caveats.add("Both runs use identical capture evidence; differences may be caused by analysis versions.");
        if (a.getCapturedAt() == null || b.getCapturedAt() == null || !a.getCapturedAt().isBefore(b.getCapturedAt()))
            caveats.add("Capture timestamps are missing, equal or reversed. This is a selected-run comparison, not verified chronological improvement.");
        if (!left.path("provenance").equals(right.path("provenance"))) caveats.add("Analysis provenance differs; rule/model/engine changes may affect results.");
        return Map.of("before", CaptureController.summary(a), "after", CaptureController.summary(b),
                "findings", changes, "servers", servers, "beforeCoverage", left.path("coverage"), "afterCoverage", right.path("coverage"), "caveats", caveats);
    }
    @PutMapping("/{id}/remediation") @Transactional
    public Map<String,String> remediation(@PathVariable Long id, @RequestBody Map<String,String> body) {
        require(id);
        String key = body.getOrDefault("key", ""), status = body.getOrDefault("status", ""), note = body.getOrDefault("note", "");
        if (key.isBlank() || key.length() > 1000 || note.length() > 2000 || !Set.of("open", "in_progress", "fix_reported").contains(status))
            throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Invalid remediation status, key or note");
        boolean known = captures.findByInvestigationIdOrderByIdDesc(id).stream().filter(c -> c.getReportJson() != null).anyMatch(c -> findings(report(c)).containsKey(key));
        if (!known) throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Finding does not belong to this investigation");
        int count = jdbc.update("update remediation_status set status=?, note=?, updated_at=? where investigation_id=? and finding_key=?", status, note, Instant.now(), id, key);
        if (count == 0) jdbc.update("insert into remediation_status(investigation_id,finding_key,status,note,updated_at) values(?,?,?,?,?)", id, key, status, note, Instant.now());
        return Map.of("key", key, "status", status, "note", note);
    }
    private Capture run(Long id, Long captureId) {
        Capture c = captures.findById(captureId).orElseThrow(() -> new IllegalArgumentException("Run not found"));
        if (!Objects.equals(id,c.getInvestigationId()) || c.getStatus() != Capture.Status.COMPLETED)
            throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Comparison requires completed runs from this investigation");
        return c;
    }
    private JsonNode report(Capture c) {
        try { return mapper.readTree(c.getReportJson()); }
        catch (Exception e) { throw new in.gov.ntro.sih.ms.service.AnalysisService.UploadRejected("Stored report cannot be read"); }
    }
    private static String identity(JsonNode s) {
        return s.path("protocol").asText() + "|" + s.path("server_name").asText("").toLowerCase(Locale.ROOT).replaceAll("\\.$", "") + "|" +
                s.path("server").path("ip").asText() + "|" + s.path("server").path("port").asText();
    }
    private static Map<String,JsonNode> findings(JsonNode report) {
        Map<String,JsonNode> out = new TreeMap<>();
        for (JsonNode s : report.path("sessions")) for (JsonNode f : s.path("findings")) {
            if (!"info".equals(f.path("severity").asText())) out.put(identity(s) + "|" + f.path("rule_id").asText(), f);
        }
        return out;
    }
    private static Map<String,Map<String,Set<String>>> serverObservations(JsonNode report) {
        Map<String,Map<String,Set<String>>> out = new TreeMap<>();
        for (JsonNode s : report.path("sessions")) {
            var entry = out.computeIfAbsent(identity(s), k -> new TreeMap<>());
            for (String field : List.of("tls_version", "cipher_suite", "starttls_accepted", "cert_visibility")) {
                if (!s.path(field).isMissingNode() && !s.path(field).isNull()) entry.computeIfAbsent(field, k -> new TreeSet<>()).add(s.path(field).asText());
            }
            for (JsonNode cert : s.path("chain")) if (cert.hasNonNull("sha256_fingerprint"))
                entry.computeIfAbsent("certificate_sha256", k -> new TreeSet<>()).add(cert.path("sha256_fingerprint").asText());
        }
        return out;
    }
}
