package io.vpndetection;

import java.time.Duration;
import java.util.Objects;

/**
 * Per-call overrides for a single lookup. Anything left unset falls back to the client's setting.
 */
public class LookupOptions {
    private Integer retries;
    private Duration requestTimeout;
    private String userAgent;

    /**
     * Retry attempts for a transient failure, for this call only.
     *
     * @throws IllegalArgumentException for a negative count, as the builder's {@code retries}
     *     does. Through 6.10.0 one was read as none, and a bogon or a cached address answered it.
     */
    public LookupOptions retries(int retries) {
        if (retries < 0) {
            throw new IllegalArgumentException("retries cannot be negative");
        }
        this.retries = retries;
        return this;
    }

    /**
     * How long one attempt may take, for this call only. The same per-attempt bound as the
     * client's {@link VPNDetection.Builder#requestTimeout}, so a retry starts a fresh one.
     */
    public LookupOptions requestTimeout(Duration requestTimeout) {
        this.requestTimeout = VPNDetection.positive(requestTimeout, "requestTimeout");
        return this;
    }

    /**
     * The {@code User-Agent} header of the request you are deciding on, sent as {@code user_agent}.
     * With every field, on a paid plan or the trial, the answer then carries {@link
     * Result#userAgent()}: the agent it names, and whether this address bears that out. Empty or
     * null sends none. Sent whatever its length: the API reads its first 1024 characters. An answer
     * for an agent is cached apart from the address's plain answer and from another agent's. A
     * bogon is answered locally and carries none.
     */
    public LookupOptions userAgent(String userAgent) {
        this.userAgent = userAgent;
        return this;
    }

    Integer retriesOrNull() {
        return retries;
    }

    Duration requestTimeoutOrNull() {
        return requestTimeout;
    }

    String userAgentOrNull() {
        return userAgent;
    }
}
