package io.vpndetection.middleware;

import io.vpndetection.Bogon;
import io.vpndetection.LookupOptions;
import io.vpndetection.Result;
import io.vpndetection.VPNDetection;
import io.vpndetection.VPNDetectionException;
import io.vpndetection.model.UserAgentVerdict;

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
    private final LookupOptions lookupOptions;
    private final Function<R, String> selector;
    private final Function<R, String> userAgentOf;
    private final List<Map<String, Object>> condition;
    private final Set<String> warned = Collections.newSetFromMap(new ConcurrentHashMap<>());

    /**
     * @param defaultIpSelector the framework's own accessor, used when the caller named none.
     */
    public Core(Options<R> options, Function<R, String> defaultIpSelector) {
        this(options, defaultIpSelector, null);
    }

    /**
     * @param defaultIpSelector the framework's own accessor, used when the caller named none.
     * @param userAgentOf the request's {@code User-Agent} header, null when absent, which {@link
     *     Options#allowBots} sends with each lookup.
     * @throws IllegalArgumentException when {@code allowBots} is on and {@code userAgentOf} is null.
     */
    public Core(Options<R> options, Function<R, String> defaultIpSelector, Function<R, String> userAgentOf) {
        Condition.validate(options.blockCondition);
        if (options.allowBots && userAgentOf == null) {
            throw new IllegalArgumentException("vpndetection: allowBots sends the request's User-Agent, "
                    + "so the Core needs a userAgentOf that reads it");
        }
        this.options = options;
        this.condition = options.blockCondition;
        this.selector = options.ipSelector != null ? options.ipSelector : defaultIpSelector;
        this.userAgentOf = options.allowBots ? userAgentOf : null;

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
        // Per call rather than only on the client built above, so an injected client is held to
        // the request path's bound too.
        this.lookupOptions = new LookupOptions().retries(options.retries).requestTimeout(options.timeout);
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

        String agent = userAgentOf == null ? null : userAgentOf.apply(request);
        boolean sendsAgent = agent != null && !agent.isEmpty();
        LookupOptions perCall = sendsAgent
                ? new LookupOptions().retries(options.retries).requestTimeout(options.timeout).userAgent(agent)
                : lookupOptions;
        Result result;
        try {
            result = client.lookup(ip, perCall);
        } catch (VPNDetectionException e) {
            return new Lookup(options.failClosed, ip, null, e);
        }
        if (condition != null) {
            reportMissing(result);
        }
        if (sendsAgent && !result.isBogon() && result.userAgent().isEmpty()) {
            report("allowBots sent the request's User-Agent, and the answer carries no user_agent "
                    + "verdict, so no crawler can be let through: it needs every field, a paid plan "
                    + "or the trial.");
        }
        // A crawler the answer verifies is never refused, whatever the condition says.
        boolean verified = result.userAgent().map(UserAgentVerdict::getVerdict)
                .map(UserAgentVerdict.VerdictEnum.VERIFIED::equals).orElse(false);
        return new Lookup(condition != null && !(userAgentOf != null && verified)
                && Condition.matches(condition, result), ip, result, null);
    }

    private void reportMissing(Result result) {
        if (options.onMissingField == Options.OnMissingField.IGNORE) {
            return;
        }
        List<String> missing = Condition.missingMembers(condition, result);
        if (missing.isEmpty()) {
            return;
        }
        report("blockCondition names " + String.join(", ", missing)
                + ", which your plan does not include, so those terms can never match. An absent "
                + "member means \"not in your plan\", not \"checked, and no\".");
    }

    // A field the answer should carry and does not, handled as onMissingField says.
    private void report(String message) {
        if (options.onMissingField == Options.OnMissingField.IGNORE) {
            return;
        }
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
