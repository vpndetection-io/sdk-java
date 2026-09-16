package io.vpndetection;

import java.time.Duration;

/**
 * Per-call overrides for one OAuth request. Anything left unset falls back to the client's setting.
 *
 * <p>No retries here: which OAuth requests are retried is fixed by what each one spends, so a token
 * exchange is never retried whatever the client says.
 */
public class OauthOptions {
    private Duration requestTimeout;

    /**
     * How long one attempt may take, for this call only. The same per-attempt bound as the client's
     * {@link VPNDetection.Builder#requestTimeout}; in {@link OauthApi#pollDeviceToken} it bounds each
     * request, never the poll as a whole.
     */
    public OauthOptions requestTimeout(Duration requestTimeout) {
        this.requestTimeout = VPNDetection.positive(requestTimeout, "requestTimeout");
        return this;
    }

    Duration requestTimeoutOrNull() {
        return requestTimeout;
    }
}
