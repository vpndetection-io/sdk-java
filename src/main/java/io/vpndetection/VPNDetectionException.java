package io.vpndetection;

import java.time.Duration;
import java.util.Optional;

/**
 * Every failure the client reports.
 *
 * <p>Unchecked, so a lookup can sit inside a stream, a lambda or a {@code CompletableFuture} chain
 * without being wrapped first. What went wrong is in {@link #kind()}, and {@link #retryable()}
 * answers whether trying again could help.
 */
public final class VPNDetectionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final ErrorKind kind;
    private final Integer statusCode;
    private final Duration retryAfter;

    public VPNDetectionException(ErrorKind kind, String message) {
        this(kind, message, null, null, null);
    }

    public VPNDetectionException(ErrorKind kind, String message, Throwable cause) {
        this(kind, message, null, null, cause);
    }

    public VPNDetectionException(
            ErrorKind kind, String message, Integer statusCode, Duration retryAfter, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.statusCode = statusCode;
        this.retryAfter = retryAfter;
    }

    public ErrorKind kind() {
        return kind;
    }

    /** The HTTP status, absent when the request never produced a response. */
    public Optional<Integer> statusCode() {
        return Optional.ofNullable(statusCode);
    }

    /**
     * How long the API asked us to wait, from its {@code Retry-After} header.
     *
     * <p>Present only on a transient rate limit. Its absence on a 429 is what marks a spent
     * allowance, which no amount of retrying will clear.
     */
    public Optional<Duration> retryAfter() {
        return Optional.ofNullable(retryAfter);
    }

    /** Whether retrying this exact request could succeed. */
    public boolean retryable() {
        return kind.retryable();
    }
}
