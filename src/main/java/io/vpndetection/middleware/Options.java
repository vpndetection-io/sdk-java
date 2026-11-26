package io.vpndetection.middleware;

import io.vpndetection.VPNDetection;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * How a middleware behaves.
 *
 * <p>Everything is optional except that you almost certainly want an {@code apiKey}: the free
 * allowance is counted per source address, and a server is one source address.
 */
public final class Options<R> {
    /** What to do when a condition names a member the plan does not serve. */
    public enum OnMissingField {
        WARN,
        THROW,
        IGNORE
    }

    // Defaults set for a request path rather than for a script: failing open quickly beats holding
    // a visitor while we try again.
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMillis(2500);
    public static final int DEFAULT_RETRIES = 0;

    VPNDetection client;
    String apiKey;
    String baseUrl;
    Duration timeout = DEFAULT_TIMEOUT;
    int retries = DEFAULT_RETRIES;
    Function<R, String> ipSelector;
    List<Map<String, Object>> blockCondition;
    boolean failClosed;
    OnMissingField onMissingField = OnMissingField.WARN;
    Predicate<R> skip;
    Consumer<String> onWarn;
    boolean allowBots;

    /**
     * An existing client to use. Prefer this if you already hold one: two clients mean two caches,
     * and a cache is per instance because two keys can be on different plans and entitled to
     * different fields.
     */
    public Options<R> client(VPNDetection client) {
        this.client = client;
        return this;
    }

    public Options<R> apiKey(String apiKey) {
        this.apiKey = apiKey;
        return this;
    }

    public Options<R> baseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
        return this;
    }

    /**
     * How long a lookup may hold the request. Defaults to 2500ms, a much tighter bound than the
     * client's own, and applied per lookup, so it holds for a {@link #client} you pass in as well.
     */
    public Options<R> timeout(Duration timeout) {
        this.timeout = timeout;
        return this;
    }

    /**
     * Retry attempts for a transient failure. Defaults to 0, unlike the client's 2.
     *
     * @throws IllegalArgumentException for a negative count, which through 6.10.0 was read as none.
     */
    public Options<R> retries(int retries) {
        if (retries < 0) {
            throw new IllegalArgumentException("retries cannot be negative");
        }
        this.retries = retries;
        return this;
    }

    /** How the client address is decided. Defaults to the framework's own accessor. */
    public Options<R> ipSelector(Function<R, String> ipSelector) {
        this.ipSelector = ipSelector;
        return this;
    }

    /**
     * What to block on. Leave it unset to only enrich the request and leave the decision to your
     * own code. A list means OR: any one entry blocking is enough.
     */
    public Options<R> blockCondition(List<Map<String, Object>> blockCondition) {
        this.blockCondition = blockCondition;
        return this;
    }

    /** What to block on, for the common single-condition case. */
    public Options<R> blockCondition(Map<String, Object> blockCondition) {
        return blockCondition(List.of(blockCondition));
    }

    /** Block when the lookup itself fails. Defaults to false, so our outage does not become yours. */
    public Options<R> failClosed(boolean failClosed) {
        this.failClosed = failClosed;
        return this;
    }

    public Options<R> onMissingField(OnMissingField onMissingField) {
        this.onMissingField = onMissingField;
        return this;
    }

    /** Skip classification for this request entirely. */
    public Options<R> skip(Predicate<R> skip) {
        this.skip = skip;
        return this;
    }

    /**
     * Let a verified crawler through. Off by default. On, a lookup sends the request's own
     * {@code User-Agent} when it names a crawler, and a request whose answer's {@code user_agent}
     * verdict is {@code verified} is never refused, whatever its condition matches; the answer is
     * still attached. Any other agent, an absent or an empty header sends none, since its verdict
     * could only be {@code not_bot}. One address is looked up with at most {@link
     * Core#MAX_AGENTS_PER_ADDRESS} crawler agents an hour: past those its lookup sends none, and a
     * request passes as a crawler only where the answer's {@code bot.verified} is true. The verdict
     * needs every field, a paid plan or the trial: once an agent was sent and a served answer
     * carries no verdict, that is reported once under {@link #onMissingField}. Off, no agent is
     * sent, so the client's cache keeps one entry per address rather than one per agent. A
     * condition naming {@code user_agent} (refusing a {@code spoofed} crawler) can match only with
     * this on, and is no plan gap for a request that sent no agent.
     */
    public Options<R> allowBots(boolean allowBots) {
        this.allowBots = allowBots;
        return this;
    }

    /** Where warnings go. Defaults to System.Logger. */
    public Options<R> onWarn(Consumer<String> onWarn) {
        this.onWarn = onWarn;
        return this;
    }
}
