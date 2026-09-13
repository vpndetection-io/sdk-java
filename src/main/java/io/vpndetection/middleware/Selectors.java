package io.vpndetection.middleware;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * The shared client-address selectors, bound to one framework's request type.
 *
 * <p>There is no portable default: a framework's own accessor may return the socket peer, or may
 * already have walked a proxy chain, depending on the framework and on how the application
 * configured it. You know your framework and your edge, so this is yours to choose.
 */
public final class Selectors<R> {
    private final Function<R, RequestView> view;

    public Selectors(Function<R, RequestView> view) {
        this.view = view;
    }

    /** The framework's own client-address accessor. */
    public Function<R, String> defaultSelector() {
        return request -> view.apply(request).frameworkIp().get();
    }

    /**
     * An address from {@code X-Forwarded-For}.
     *
     * <p>The LEFT-MOST entry ({@code depth} 0) is whatever the caller sent, because proxies append
     * to this header, so a visitor who sets it themselves appears first and this returns their
     * forgery. It is only trustworthy when an edge you control overwrites the header. When you know
     * how many proxies sit in front, count from the right: depth 1 is the address your nearest
     * proxy saw.
     */
    public Function<R, String> forwardedFor(int depth) {
        return request -> {
            RequestView seen = view.apply(request);
            String raw = seen.header().apply("X-Forwarded-For");
            List<String> chain = new ArrayList<>();
            if (raw != null) {
                for (String entry : raw.split(",")) {
                    String trimmed = entry.trim();
                    if (!trimmed.isEmpty()) {
                        chain.add(trimmed);
                    }
                }
            }
            if (chain.isEmpty()) {
                return seen.frameworkIp().get();
            }
            if (depth <= 0 || depth > chain.size()) {
                return chain.get(0);
            }
            return chain.get(chain.size() - depth);
        };
    }

    /**
     * An address from a single-value header your edge writes - {@code header("CF-Connecting-IP")}
     * behind Cloudflare. Falls back to the framework's accessor when the header is absent.
     */
    public Function<R, String> header(String name) {
        return request -> {
            RequestView seen = view.apply(request);
            String value = seen.header().apply(name);
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
            return seen.frameworkIp().get();
        };
    }
}
