package io.vpndetection.middleware;

import io.vpndetection.Bogon;
import io.vpndetection.LookupOptions;
import io.vpndetection.Result;
import io.vpndetection.VPNDetection;
import io.vpndetection.VPNDetectionException;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * The framework-agnostic half of a web middleware: resolve a client address, classify it, and
 * decide whether the condition matched.
 *
 * <p>An adapter - the Spring Boot starter - keeps only the parts that are genuinely
 * framework-shaped and shares everything here, so the shared conformance corpus is asserted once
 * for Java rather than once per framework.
 */
public final class Core<R> {
    private static final System.Logger LOG = System.getLogger("io.vpndetection");

    private final Options<R> options;
    private final VPNDetection client;
    private final Function<R, String> selector;
    private final List<Map<String, Object>> condition;
    private final Set<String> warned = Collections.newSetFromMap(new ConcurrentHashMap<>());

    /**
     * @param defaultIpSelector the framework's own accessor, used when the caller named none.
     */
    public Core(Options<R> options, Function<R, String> defaultIpSelector) {
        Condition.validate(options.blockCondition);
        this.options = options;
        this.condition = options.blockCondition;
        this.selector = options.ipSelector != null ? options.ipSelector : defaultIpSelector;

        if (options.client != null) {
            this.client = options.client;
        } else {
            VPNDetection.Builder builder = VPNDetection.builder()
                    .retries(options.retries)
                    .requestTimeout(options.timeout);
            if (options.apiKey != null) {
                builder.apiKey(options.apiKey);
            }
            if (options.baseUrl != null) {
                builder.baseUrl(options.baseUrl);
            }
            this.client = builder.build();
        }
    }

    /** Whether a condition was configured at all. */
    public boolean isBlocking() {
        return condition != null;
    }

    /**
     * Classify one request. Answers null when {@code skip} claimed it.
     *
     * <p>A failed LOOKUP is not thrown: it lands on {@link Lookup#error()} and the request is let
     * through. What CAN throw is a misconfiguration - a condition naming a member the plan does not
     * serve, with {@code onMissingField} set to THROW.
     */
    public Lookup evaluate(R request) {
        if (options.skip != null && options.skip.test(request)) {
            return null;
        }
        String resolved = selector.apply(request);
        String ip = resolved == null ? "" : resolved.trim();
        if (ip.isEmpty()) {
            warn("could not resolve a client address from this request; pass an ipSelector that "
                    + "knows where yours comes from");
            return new Lookup(options.failClosed, null, null,
                    new VPNDetectionException(io.vpndetection.ErrorKind.BAD_REQUEST,
                            "no client address on the request"));
        }
        if (Bogon.isBogon(ip)) {
            // Expected in local development. Anywhere else it means a proxy sits in front and its
            // own address is what reached us.
            warn("resolved the client address as " + ip + ", which is not a public address. If "
                    + "this application runs behind a proxy or load balancer, configure its "
                    + "trusted-proxy setting or pass an ipSelector that reads your edge's header.");
        }

        Result result;
        try {
            result = client.lookup(ip, new LookupOptions().retries(options.retries));
        } catch (VPNDetectionException e) {
            return new Lookup(options.failClosed, ip, null, e);
        }
        if (condition != null) {
            reportMissing(result);
        }
        return new Lookup(
                condition != null && Condition.matches(condition, result), ip, result, null);
    }

    private void reportMissing(Result result) {
        if (options.onMissingField == Options.OnMissingField.IGNORE) {
            return;
        }
        List<String> missing = Condition.missingMembers(condition, result);
        if (missing.isEmpty()) {
            return;
        }
        String message = "blockCondition names " + String.join(", ", missing)
                + ", which your plan does not include, so those terms can never match. An absent "
                + "member means \"not in your plan\", not \"checked, and no\".";
        if (options.onMissingField == Options.OnMissingField.THROW) {
            throw new IllegalStateException("vpndetection: " + message);
        }
        warn(message);
    }

    // A misconfiguration is the same on every request, so saying so once is a warning and saying
    // so a million times is an outage of its own.
    private void warn(String message) {
        if (!warned.add(message)) {
            return;
        }
        if (options.onWarn != null) {
            options.onWarn.accept(message);
        } else {
            LOG.log(System.Logger.Level.WARNING, message);
        }
    }
}
