package in.gov.ntro.sih.ms.engine;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;
import org.springframework.stereotype.Component;

/** A bounded process boundary: deadline includes stdout/stderr reads and stdin writes. */
@Component
public class EngineClient {
    private final EngineProperties properties;
    private final ObjectMapper mapper = new ObjectMapper();
    public EngineClient(EngineProperties properties) { this.properties = properties; }
    public static class EngineException extends RuntimeException {
        public EngineException(String message) { super(message); }
        public EngineException(String message, Throwable cause) { super(message, cause); }
    }
    public JsonNode analyse(Path pcap) { return analyse(pcap, null, s -> {}, () -> false); }
    public JsonNode analyse(Path pcap, Path history, Consumer<String> progress, BooleanSupplier cancelled) {
        List<String> command = command("analyse", pcap.toAbsolutePath().toString(), "--json", "-", "--compact");
        if (!properties.isMlEnabled()) command.add("--no-ml");
        if (history != null) { command.add("--history"); command.add(history.toString()); }
        try { return mapper.readTree(run(command, null, properties.getTimeoutSeconds(), progress, cancelled)); }
        catch (IOException e) { throw new EngineException("Engine output was not valid JSON", e); }
    }
    public byte[] render(String reportJson) {
        return run(command("render", "-", "--html", "-"), reportJson.getBytes(StandardCharsets.UTF_8),
                properties.getTimeoutSeconds(), s -> {}, () -> false);
    }
    private List<String> command(String... args) {
        List<String> command = new ArrayList<>(properties.pythonCommand());
        command.add("-m"); command.add("mailsentinel.cli"); command.addAll(List.of(args)); return command;
    }
    private byte[] run(List<String> command, byte[] input, long timeout, Consumer<String> progress, BooleanSupplier cancelled) {
        Process process;
        try { process = new ProcessBuilder(command).start(); }
        catch (IOException e) { throw new EngineException("Could not start analysis engine; configure SMS_PYTHON: " + e.getMessage(), e); }
        ExecutorService pumps = Executors.newFixedThreadPool(3, task -> {
            Thread thread = new Thread(task, "engine-io"); thread.setDaemon(true); return thread;
        });
        Future<byte[]> stdout = pumps.submit(() -> readLimited(process.getInputStream(), 64 * 1024 * 1024));
        Future<String> stderr = pumps.submit(() -> {
            StringBuilder tail = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.matches("SMS_PROGRESS:[A-Z_]{1,50}")) progress.accept(line.substring(13));
                    else { tail.append(line).append('\n'); if (tail.length() > 4000) tail.delete(0, tail.length() - 4000); }
                }
            }
            return tail.toString();
        });
        Future<?> writer = pumps.submit(() -> {
            try (OutputStream out = process.getOutputStream()) { if (input != null) out.write(input); }
            catch (IOException e) { throw new UncheckedIOException(e); }
        });
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        try {
            while (!process.waitFor(200, TimeUnit.MILLISECONDS)) {
                if (cancelled.getAsBoolean()) throw new EngineException("Analysis cancelled");
                if (System.nanoTime() >= deadline) throw new EngineException("Engine timed out after " + timeout + "s");
                if (stdout.isDone()) stdout.get(); // surfaces output-size/read failures while still running
                if (stderr.isDone()) stderr.get();
            }
            if (cancelled.getAsBoolean()) throw new EngineException("Analysis cancelled");
            long remaining = Math.max(1, deadline - System.nanoTime());
            byte[] result = stdout.get(remaining, TimeUnit.NANOSECONDS);
            String diagnostics = stderr.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (process.exitValue() != 0) throw new EngineException("Engine exited with status " + process.exitValue() + ": " + diagnostics);
            writer.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
            if (result.length == 0) throw new EngineException("Engine produced no output: " + diagnostics);
            return result;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); throw new EngineException("Engine interrupted", e);
        } catch (ExecutionException | TimeoutException e) {
            throw new EngineException("Engine output failed or exceeded its deadline: " + e.getMessage(), e);
        } finally {
            process.descendants().forEach(ProcessHandle::destroyForcibly);
            if (process.isAlive()) process.destroyForcibly();
            pumps.shutdownNow();
        }
    }
    private static byte[] readLimited(InputStream stream, int max) throws IOException {
        try (stream; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192]; int n;
            while ((n = stream.read(buffer)) != -1) {
                if (out.size() + n > max) throw new IOException("Report exceeds 64 MB process-output limit");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }
    public record EngineStatus(boolean ready, String version, String error, String python, String interpreter) {
        public static EngineStatus down(String error) { return new EngineStatus(false, null, error, null, null); }
    }
    public EngineStatus probe() {
        List<String> cmd = new ArrayList<>(properties.pythonCommand());
        cmd.add("-c"); cmd.add("import sys;import mailsentinel.pipeline;print('1.1.0');print(sys.version.split()[0]);print(sys.executable)");
        try {
            String[] out = new String(run(cmd, null, 30, s -> {}, () -> false), StandardCharsets.UTF_8).trim().split("\\R");
            return new EngineStatus(true, out[0], null, out[1], out[2]);
        } catch (Exception e) { return EngineStatus.down(e.getMessage()); }
    }
    public String version() { return probe().version(); }
}
