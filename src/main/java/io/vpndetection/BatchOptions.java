package io.vpndetection;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-call overrides for one batch. Anything left unset falls back to the client's setting.
 *
 * <p>A caller with one big batch should not have to build a second client to widen it, which is why
 * concurrency is settable here and not only on the builder.
 */
public final class BatchOptions extends LookupOptions {
    private Integer concurrency;
    private Map<String, String> userAgents = Map.of();

    /**
     * Concurrent batch requests - chunks of up to 1000 addresses - for THIS batch only. Below 1, the
     * batch is refused as {@link ErrorKind#BAD_REQUEST} before any request.
     */
    public BatchOptions concurrency(int concurrency) {
        this.concurrency = concurrency;
        return this;
    }

    @Override
    public BatchOptions retries(int retries) {
        super.retries(retries);
        return this;
    }

    /** How long one attempt at one chunk may take, for THIS batch only. */
    @Override
    public BatchOptions requestTimeout(Duration requestTimeout) {
        super.requestTimeout(requestTimeout);
        return this;
    }

    /**
     * The user agent sent with every address of THIS batch, bar one {@link #userAgents} names. A
     * request keys {@code user_agents} by address, so one address asked with two agents is asked in
     * two requests.
     */
    @Override
    public BatchOptions userAgent(String userAgent) {
        super.userAgent(userAgent);
        return this;
    }

    /**
     * Each address's user agent, keyed by the address exactly as passed to the batch, sent as
     * {@code user_agents} keyed by the address as the request carries it, and only in a request
     * where an address has one. An empty agent is none. Copied when set.
     */
    public BatchOptions userAgents(Map<String, String> userAgents) {
        this.userAgents = userAgents == null ? Map.of() : new LinkedHashMap<>(userAgents);
        return this;
    }

    Map<String, String> userAgentsOrEmpty() {
        return userAgents;
    }

    Integer concurrencyOrNull() {
        return concurrency;
    }
}
