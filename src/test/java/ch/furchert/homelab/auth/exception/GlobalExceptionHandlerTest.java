package ch.furchert.homelab.auth.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(OutputCaptureExtension.class)
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void noResourceFoundKeeps404WithoutLoggingOrEchoingThePath(CapturedOutput output) {
        ResponseEntity<Map<String, Object>> response =
                handler.handleGeneric(new NoResourceFoundException(HttpMethod.GET, "/x/wa147-path", "x/wa147-path"));

        assertThat(response.getStatusCode().value()).isEqualTo(404);
        assertThat(response.getBody()).containsEntry("status", 404).containsEntry("error", "Not Found");
        assertThat(response.getBody().toString()).doesNotContain("wa147-path");
        assertThat(output).doesNotContain("Unhandled exception");
    }

    @Test
    void unsupportedMethodKeeps405AndTheAllowHeader() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleGeneric(new HttpRequestMethodNotSupportedException("PATCH", List.of("GET", "PUT")));

        assertThat(response.getStatusCode().value()).isEqualTo(405);
        assertThat(response.getHeaders().getAllow()).extracting(HttpMethod::name).contains("GET", "PUT");
        assertThat(response.getBody()).containsEntry("error", "Method Not Allowed");
    }

    @Test
    void unexpectedExceptionStillAnswers500AndLogsAtError(CapturedOutput output) {
        ResponseEntity<Map<String, Object>> response = handler.handleGeneric(new IllegalStateException("boom"));

        assertThat(response.getStatusCode().value()).isEqualTo(500);
        assertThat(response.getBody()).containsEntry("error", "Internal server error");
        assertThat(output).contains("Unhandled exception");
    }
}
