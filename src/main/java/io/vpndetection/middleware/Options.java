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

    /** Retry attempts for a transient failure. Defaults to 0, unlike the client's 2. */
    public Options<R> retries(int retries) {
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

    /** Where warnings go. Defaults to System.Logger. */
    public Options<R> onWarn(Consumer<String> onWarn) {
        this.onWarn = onWarn;
        return this;
    }
}
