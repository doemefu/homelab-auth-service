package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.repository.LoginEventOutboxRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class LoginEventRecorderTest {

    private static LoginEvent event() {
        return new LoginEvent(UUID.randomUUID(), Instant.now(), LoginEvent.FAILURE, "203.0.113.7",
                "cf-connecting-ip", "a".repeat(64), null, "Mozilla/5.0 TestAgent");
    }

    @Test
    void fullQueueDropsEventsWithoutThrowing() throws Exception {
        LoginEventOutboxRepository repo = mock(LoginEventOutboxRepository.class);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(inv -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return null;
        }).when(repo).insert(any());
        LoginEventProperties props = new LoginEventProperties();
        props.setQueueCapacity(1);
        LoginEventRecorder recorder = new LoginEventRecorder(repo, props);

        recorder.submit(event());                       // runs, blocks in insert
        assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();
        recorder.submit(event());                       // queued (capacity 1)
        assertThatCode(() -> {
            recorder.submit(event());                   // dropped
            recorder.submit(event());                   // dropped
        }).doesNotThrowAnyException();

        release.countDown();
        recorder.shutdown();
        verify(repo, times(2)).insert(any());
    }

    @Test
    void insertFailureIsSwallowed() throws Exception {
        LoginEventOutboxRepository repo = mock(LoginEventOutboxRepository.class);
        doThrow(new IllegalStateException("db down")).when(repo).insert(any());
        LoginEventRecorder recorder = new LoginEventRecorder(repo, new LoginEventProperties());

        assertThatCode(() -> recorder.submit(event())).doesNotThrowAnyException();
        recorder.shutdown();
        verify(repo, timeout(2000)).insert(any());
    }

    @Test
    void toStringHidesPersonalData() {
        assertThat(event().toString()).doesNotContain("203.0.113.7").doesNotContain("TestAgent");
    }
}
