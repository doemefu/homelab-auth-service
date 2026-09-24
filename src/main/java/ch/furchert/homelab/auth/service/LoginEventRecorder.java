package ch.furchert.homelab.auth.service;

import ch.furchert.homelab.auth.config.LoginEventProperties;
import ch.furchert.homelab.auth.repository.LoginEventOutboxRepository;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Inserts captured login events off the login path on one daemon thread with a bounded queue
 * (docs/060 §7.6). A full queue drops the event: telemetry must never fail or slow a login.
 * Drops and insert errors are logged at WARN (expected backpressure, not a Sentry-worthy ERROR),
 * rate-limited, and without IPs, usernames or user agents.
 */
@Component
@Slf4j
public class LoginEventRecorder {

    static final long DROP_WARN_INTERVAL_NANOS = TimeUnit.MINUTES.toNanos(1);

    private final LoginEventOutboxRepository repository;
    private final ThreadPoolExecutor executor;
    private final AtomicLong droppedSinceLastWarn = new AtomicLong();
    private final AtomicLong lastDropWarnNanos = new AtomicLong(System.nanoTime() - DROP_WARN_INTERVAL_NANOS);

    public LoginEventRecorder(LoginEventOutboxRepository repository, LoginEventProperties properties) {
        this.repository = repository;
        this.executor = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(Math.max(1, properties.getQueueCapacity())),
                runnable -> {
                    Thread t = new Thread(runnable, "login-event-recorder");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    public void submit(LoginEvent event) {
        try {
            executor.execute(() -> insert(event));
        } catch (RejectedExecutionException e) {
            long dropped = droppedSinceLastWarn.incrementAndGet();
            long now = System.nanoTime();
            long last = lastDropWarnNanos.get();
            if (now - last >= DROP_WARN_INTERVAL_NANOS && lastDropWarnNanos.compareAndSet(last, now)) {
                droppedSinceLastWarn.addAndGet(-dropped);
                log.warn("Login-event queue full; dropped {} event(s) in the last interval", dropped);
            }
        }
    }

    private void insert(LoginEvent event) {
        try {
            repository.insert(event);
        } catch (RuntimeException e) {
            // Class name only: the driver message could echo parameter values (IPs, usernames).
            log.warn("Could not store login event: {}", e.getClass().getSimpleName());
        }
    }

    @PreDestroy
    void shutdown() throws InterruptedException {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }
}
