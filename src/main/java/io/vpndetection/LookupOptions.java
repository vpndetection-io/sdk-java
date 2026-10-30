package io.vpndetection;

import java.time.Duration;
import java.util.Objects;

/**
 * Per-call overrides for a single lookup. Anything left unset falls back to the client's setting.
 */
public class LookupOptions {
    private Integer retries;
    private Duration requestTimeout;

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

    Integer retriesOrNull() {
        return retries;
    }

    Duration requestTimeoutOrNull() {
        return requestTimeout;
    }
}
