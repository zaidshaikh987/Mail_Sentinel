package in.gov.ntro.sih.ms.web;

import in.gov.ntro.sih.ms.engine.EngineClient;
import in.gov.ntro.sih.ms.service.AnalysisService;
import java.time.Instant;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/** Errors explain what went wrong and what to do about it — never a bare stack trace. */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AnalysisService.UploadRejected.class)
    public ResponseEntity<Map<String, Object>> rejected(AnalysisService.UploadRejected e) {
        return body(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> tooLarge(MaxUploadSizeExceededException e) {
        return body(HttpStatus.PAYLOAD_TOO_LARGE,
                "That capture is larger than the configured upload limit. "
                        + "Raise spring.servlet.multipart.max-file-size to accept it.");
    }

    @ExceptionHandler(EngineClient.EngineException.class)
    public ResponseEntity<Map<String, Object>> engine(EngineClient.EngineException e) {
        return body(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
    }


    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> notFound(IllegalArgumentException e) {
        return body(HttpStatus.NOT_FOUND, e.getMessage());
    }

    private static ResponseEntity<Map<String, Object>> body(HttpStatus status, String message) {
        return ResponseEntity.status(status).body(Map.of(
                "status", status.value(),
                "error", status.getReasonPhrase(),
                "message", message == null ? "unexpected error" : message,
                "timestamp", Instant.now().toString()));
    }
}
