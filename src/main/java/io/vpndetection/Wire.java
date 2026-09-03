package io.vpndetection;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.internal.ApiException;

import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * The seam between the generated wire layer and this one: retries, and the generated
 * {@link ApiException} turned into a {@link VPNDetectionException}.
 */
final class Wire {
    private Wire() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration BACKOFF_BASE = Duration.ofMillis(200);
    private static final Duration BACKOFF_CAP = Duration.ofSeconds(8);

    interface Call<T> {
        T invoke() throws ApiException;
    }

    /**
     * Runs a generated call, retrying a transient failure up to {@code retries} times.
     *
     * <p>A server-supplied {@code Retry-After} wins over the backoff schedule, and is also the only
     * thing that makes a 429 retryable at all.
     */
    static <T> T execute(int retries, Call<T> call) {
        for (int attempt = 0; ; attempt++) {
            VPNDetectionException failure;
            try {
                return call.invoke();
            } catch (ApiException e) {
                failure = translate(e);
            }
            if (attempt >= retries || !failure.retryable()) {
                throw failure;
            }
            Duration asked = failure.retryAfter().orElse(null);
            sleep(asked != null ? asked : backoff(attempt));
        }
    }

    static VPNDetectionException translate(ApiException e) {
        int status = e.getCode();
        if (status == 0) {
            return new VPNDetectionException(ErrorKind.NETWORK, messageOf(e), null, null, e.getCause());
        }
        Duration retryAfter = retryAfterOf(e);
        ErrorKind kind;
        switch (status) {
            case 400:
                kind = ErrorKind.BAD_REQUEST;
                break;
            case 401:
                kind = ErrorKind.UNAUTHORIZED;
                break;
            case 403:
                kind = ErrorKind.FORBIDDEN;
                break;
            case 429:
                // Present means transient, absent means an allowance is spent. Nothing else in the
                // response separates the two.
                kind = retryAfter == null ? ErrorKind.QUOTA_EXCEEDED : ErrorKind.RATE_LIMITED;
                break;
            default:
                kind = ErrorKind.SERVER_ERROR;
                break;
        }
        return new VPNDetectionException(kind, messageOf(e), status, retryAfter, null);
    }

    // The two APIs behind this host answer with different envelopes: the lookup endpoint uses
    // `error`, the database endpoints use `rc`. Both are read here so a caller never has to know
    // which one they hit.
    private static String messageOf(ApiException e) {
        String body = e.getResponseBody();
        if (body != null && !body.isBlank()) {
            try {
                JsonNode root = MAPPER.readTree(body);
                for (String field : new String[] {"error", "rc"}) {
                    JsonNode value = root.get(field);
                    if (value != null && value.isTextual()) {
                        return value.asText();
                    }
                }
            } catch (Exception ignored) {
                // A non-JSON body is not worth failing over; fall through to the generic message.
            }
        }
        if (e.getCode() != 0) {
            return "request failed with status " + e.getCode();
        }
        Throwable cause = e.getCause();
        return cause != null && cause.getMessage() != null ? cause.getMessage() : "request failed";
    }

    private static Duration retryAfterOf(ApiException e) {
        if (e.getResponseHeaders() == null) {
            return null;
        }
        String value = e.getResponseHeaders().firstValue("Retry-After").orElse(null);
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            long seconds = Long.parseLong(value.trim());
            return seconds >= 0 ? Duration.ofSeconds(seconds) : null;
        } catch (NumberFormatException notSeconds) {
            // The header also permits an HTTP date.
        }
        try {
            ZonedDateTime when = ZonedDateTime.parse(value.trim(), DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration wait = Duration.between(Instant.now(), when.toInstant());
            return wait.isNegative() ? Duration.ZERO : wait;
        } catch (DateTimeParseException notADate) {
            return null;
        }
    }

    private static Duration backoff(int attempt) {
        Duration wait = BACKOFF_BASE.multipliedBy(1L << Math.min(attempt, 16));
        return wait.compareTo(BACKOFF_CAP) > 0 ? BACKOFF_CAP : wait;
    }

    private static void sleep(Duration wait) {
        if (wait.isZero() || wait.isNegative()) {
            return;
        }
        try {
            Thread.sleep(wait.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VPNDetectionException(ErrorKind.NETWORK, "interrupted while waiting to retry", e);
        }
    }
}
