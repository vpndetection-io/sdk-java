package io.vpndetection.middleware;

import io.vpndetection.Result;
import io.vpndetection.VPNDetectionException;

import java.util.Optional;

/** What a middleware attached to the request, whether or not it succeeded. */
public final class Lookup {
    private final boolean blocked;
    private final String ip;
    private final Result result;
    private final VPNDetectionException error;

    Lookup(boolean blocked, String ip, Result result, VPNDetectionException error) {
        this.blocked = blocked;
        this.ip = ip;
        this.result = result;
        this.error = error;
    }

    /** Whether the condition matched. Always false when no condition was configured. */
    public boolean isBlocked() {
        return blocked;
    }

    /** The address that was classified, as the selector resolved it. */
    public Optional<String> ip() {
        return Optional.ofNullable(ip);
    }

    /** The answer. Empty when the lookup failed. */
    public Optional<Result> result() {
        return Optional.ofNullable(result);
    }

    /** Why the lookup failed. Empty when it succeeded. */
    public Optional<VPNDetectionException> error() {
        return Optional.ofNullable(error);
    }
}
