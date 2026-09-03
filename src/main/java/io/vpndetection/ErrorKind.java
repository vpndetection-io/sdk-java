package io.vpndetection;

/**
 * Why a request failed.
 *
 * <p>{@link #RATE_LIMITED} and {@link #QUOTA_EXCEEDED} both arrive as HTTP 429 and are NOT the
 * same thing. A rate limit is the API protecting itself and carries {@code Retry-After}; retrying
 * works. A spent quota carries no such header and retrying will not help until the window rolls
 * over or the limit is raised. The header is the only thing that distinguishes them.
 */
public enum ErrorKind {
    BAD_REQUEST,
    UNAUTHORIZED,
    FORBIDDEN,
    RATE_LIMITED,
    QUOTA_EXCEEDED,
    SERVER_ERROR,
    NETWORK;

    /** Whether retrying the exact same request could succeed. */
    public boolean retryable() {
        return this == RATE_LIMITED || this == SERVER_ERROR || this == NETWORK;
    }
}
