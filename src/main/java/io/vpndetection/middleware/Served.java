package io.vpndetection.middleware;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.vpndetection.Result;
import io.vpndetection.internal.ApiClient;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link Result} as the wire described it, for a condition to match against.
 *
 * <p>Built from the Result's own accessors rather than by serializing it, and that is the whole
 * point: an empty {@code Optional} means "not in your plan" and has to come out as an ABSENT key,
 * which a serializer's null-inclusion setting would decide for us - differently depending on how
 * it happened to be configured.
 */
final class Served {
    // The SDK's own mapper, not a bare one: the generated detail models carry
    // java.time.LocalDate for last_seen/first_seen, which a default ObjectMapper refuses outright.
    // Using the same mapper that PARSED the response is also the only way this projection cannot
    // disagree with it.
    private static final ObjectMapper MAPPER = ApiClient.createDefaultObjectMapper();

    private Served() {}

    static Map<String, Object> of(Result result) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ip", result.ip());
        out.put("is_vpn", result.isVpn());
        put(out, "is_hosting", result.isHosting());
        put(out, "is_relay", result.isRelay());
        put(out, "is_tor", result.isTor());
        put(out, "is_cdn", result.isCdn());
        put(out, "is_resproxy", result.isResproxy());
        put(out, "is_dcproxy", result.isDcproxy());
        put(out, "is_mobproxy", result.isMobproxy());
        putDetail(out, "vpn", result.vpn());
        putDetail(out, "hosting", result.hosting());
        putDetail(out, "relay", result.relay());
        putDetail(out, "tor", result.tor());
        putDetail(out, "cdn", result.cdn());
        putDetail(out, "resproxy", result.resproxy());
        putDetail(out, "dcproxy", result.dcproxy());
        putDetail(out, "mobproxy", result.mobproxy());
        return out;
    }

    private static void put(Map<String, Object> out, String key, Optional<Boolean> value) {
        value.ifPresent(v -> out.put(key, v));
    }

    // The detail objects carry their wire names on @JsonProperty, so Jackson is what turns one
    // into the shape a condition is written against. Their fields are flat scalars, so nothing
    // here depends on how nulls are included: a null simply matches nothing.
    private static void putDetail(Map<String, Object> out, String key, Optional<?> value) {
        value.ifPresent(v -> out.put(key, MAPPER.convertValue(v, Map.class)));
    }
}
