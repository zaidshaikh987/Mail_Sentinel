package in.gov.ntro.sih.ms;
import static org.assertj.core.api.Assertions.*;
import in.gov.ntro.sih.ms.engine.*;
import java.nio.file.*;
import java.time.*;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class EngineBoundaryTest {
    @TempDir Path temp;
    EngineClient client(String script, int timeout) throws Exception {
        Path file = temp.resolve("engine.py"); Files.writeString(file, script);
        EngineProperties p = new EngineProperties();
        p.setPython(System.getenv().getOrDefault("SMS_PYTHON", "python3") + " " + file);
        p.setTimeoutSeconds(timeout);
        return new EngineClient(p);
    }
    @Test void deadlineAppliesEvenWhenStdoutNeverCloses() throws Exception {
        EngineClient c = client("import time\ntime.sleep(30)\n", 1);
        Instant start = Instant.now();
        assertThatThrownBy(() -> c.analyse(temp.resolve("x"))).hasMessageContaining("timed out");
        assertThat(Duration.between(start,Instant.now()).toSeconds()).isLessThan(6);
    }
    @Test void cancellationTerminatesActiveProcess() throws Exception {
        EngineClient c = client("import time\ntime.sleep(30)\n", 30);
        assertThatThrownBy(() -> c.analyse(temp.resolve("x"),null,s -> {},() -> true)).hasMessageContaining("cancelled");
    }
    @Test void progressAndOutputUseSeparateChannels() throws Exception {
        EngineClient c = client("import sys,json\nprint('SMS_PROGRESS:READING',file=sys.stderr,flush=True)\nprint(json.dumps({'sessions':[]}))\n", 5);
        var stages = new ArrayList<String>();
        assertThat(c.analyse(temp.resolve("x"),null,stages::add,() -> false).path("sessions").isArray()).isTrue();
        assertThat(stages).containsExactly("READING");
    }
}
