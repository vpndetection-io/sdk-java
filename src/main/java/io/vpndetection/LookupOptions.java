package io.vpndetection;

/**
 * Per-call overrides for a single lookup. Anything left unset falls back to the client's setting.
 */
public class LookupOptions {
    private Integer retries;

    /** Retry attempts for a transient failure, for this call only. */
    public LookupOptions retries(int retries) {
        this.retries = retries;
        return this;
    }

    Integer retriesOrNull() {
        return retries;
    }
}
