package io.vpndetection.middleware;

import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Enough of an incoming request for a selector to work with, whatever framework it came from. An
 * adapter supplies one of these per request.
 *
 * @param header a request header by name, case-insensitively; null when absent
 * @param frameworkIp the framework's own client-address accessor, whatever that resolves to here
 */
public record RequestView(Function<String, String> header, Supplier<String> frameworkIp) {}
