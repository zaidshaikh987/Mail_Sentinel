package in.gov.ntro.sih.ms.engine;

import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for running the Python analysis engine.
 *
 * <p>There is exactly one knob that matters: {@code ms.engine.python}, the
 * interpreter to run. The engine is an installed package in that interpreter's
 * environment, so it is found by import like any other library.
 *
 * <p>This used to also carry {@code ms.engine.path}, a directory that was put
 * on {@code PYTHONPATH} and used as the subprocess working directory so the
 * engine could run "straight from a source checkout". That convenience was the
 * single largest source of divergence between running locally and running in
 * Docker: the image had the engine installed in a virtualenv *and* a copy on
 * PYTHONPATH, and which one actually executed depended on the working
 * directory. Two copies of the analysis engine, silently interchangeable, is
 * not a property a forensic tool should have — a trained model written to one
 * of them is invisible to the other. Install the engine; import it; one copy.
 */
@ConfigurationProperties(prefix = "ms.engine")
public class EngineProperties {

    private static final Logger log = LoggerFactory.getLogger(EngineProperties.class);

    /** Interpreter to run. A virtualenv's python goes here. */
    private String python = "python3";

    /** Where the bundled demo captures live, resolved against the working directory. */
    private String demoDir = "demo-pcaps";

    /** Where uploaded captures are stored. */
    private String uploadDir = "./data/uploads";

    /** Maximum time a single analysis may take. */
    private int timeoutSeconds = 300;

    /** Whether to run the model stage. Rules are unaffected either way. */
    private boolean mlEnabled = true;

    /** Reject uploads larger than this (bytes). */
    private long maxUploadBytes = 2L * 1024 * 1024 * 1024;

    @PostConstruct
    void report() {
        log.info("analysis engine interpreter: {}", String.join(" ", pythonCommand()));
        Path demo = resolvedDemoDir();
        if (!Files.isDirectory(demo)) {
            log.warn("demo capture directory '{}' does not exist — the bundled captures "
                    + "will not be offered", demo.toAbsolutePath());
        }
    }

    /**
     * Split the configured interpreter so values like {@code "python3 -X utf8"}
     * or a venv path with arguments work.
     */
    public List<String> pythonCommand() {
        List<String> parts = new ArrayList<>(Arrays.asList(python.trim().split("\\s+")));
        parts.removeIf(String::isEmpty);
        return parts.isEmpty() ? List.of("python3") : parts;
    }

    public Path resolvedDemoDir() {
        Path p = Paths.get(demoDir);
        return p.isAbsolute() ? p : Paths.get("").toAbsolutePath().resolve(p).normalize();
    }

    public Path resolvedUploadDir() {
        Path p = Paths.get(uploadDir);
        return p.isAbsolute() ? p : Paths.get("").toAbsolutePath().resolve(p).normalize();
    }

    public String getPython() { return python; }
    public void setPython(String python) { this.python = python; }
    public String getDemoDir() { return demoDir; }
    public void setDemoDir(String demoDir) { this.demoDir = demoDir; }
    public String getUploadDir() { return uploadDir; }
    public void setUploadDir(String uploadDir) { this.uploadDir = uploadDir; }
    public int getTimeoutSeconds() { return timeoutSeconds; }
    public void setTimeoutSeconds(int timeoutSeconds) { this.timeoutSeconds = timeoutSeconds; }
    public boolean isMlEnabled() { return mlEnabled; }
    public void setMlEnabled(boolean mlEnabled) { this.mlEnabled = mlEnabled; }
    public long getMaxUploadBytes() { return maxUploadBytes; }
    public void setMaxUploadBytes(long maxUploadBytes) { this.maxUploadBytes = maxUploadBytes; }
}
