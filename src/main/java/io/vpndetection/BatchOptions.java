package io.vpndetection;

/**
 * Per-call overrides for one batch. Anything left unset falls back to the client's setting.
 *
 * <p>A caller with one big batch should not have to build a second client to widen it, which is why
 * concurrency is settable here and not only on the builder.
 */
public final class BatchOptions extends LookupOptions {
    private Integer concurrency;

    /** Concurrent in-flight requests for THIS batch only. */
    public BatchOptions concurrency(int concurrency) {
        this.concurrency = concurrency;
        return this;
    }

    @Override
    public BatchOptions retries(int retries) {
        super.retries(retries);
        return this;
    }

    Integer concurrencyOrNull() {
        return concurrency;
    }
}
