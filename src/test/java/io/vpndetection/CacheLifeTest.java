package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.benmanes.caffeine.cache.Ticker;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * How long an answer stays cached: the client's TTL, except an answer past the trial or the
 * overage cap, which can change as soon as the organization's trial, plan or cap does, so it stays
 * a minute at most, or the TTL where that is shorter. The cache's clock is moved rather than waited
 * on, so each row pins the expiry to the instant: still cached a millisecond before it, asked again
 * at it.
 */
class CacheLifeTest {
    private static final String IP = "8.8.8.8";

    // The flag the answer carries (none for neither), its value, the client's TTL and how long the
    // answer must stay cached, all in seconds.
    static Stream<Arguments> lives() {
        return Stream.of(
                Arguments.of("trial_expired", true, 3600, 60),
                Arguments.of("cap_reached", true, 3600, 60),
                Arguments.of("trial_expired", true, 30, 30),
                Arguments.of("cap_reached", true, 30, 30),
                Arguments.of("trial_expired", false, 3600, 3600),
                Arguments.of("cap_reached", false, 3600, 3600),
                Arguments.of(null, false, 3600, 3600),
                Arguments.of(null, false, 30, 30));
    }

    @ParameterizedTest
    @MethodSource("lives")
    void aLookupsAnswerStaysCachedForItsLife(String flag, boolean value, int ttl, int life) {
        AtomicLong now = new AtomicLong();
        StubHttpClient http = StubHttpClient.of(Map.of(IP, StubHttpClient.Route.ok(body(flag, value))));
        try (VPNDetection client = client(http, now, ttl)) {
            client.lookup(IP);
            now.addAndGet(Duration.ofSeconds(life).minusMillis(1).toNanos());
            client.lookup(IP);
            assertEquals(1, http.calls.size(), "still cached a millisecond before its life ends");

            now.addAndGet(Duration.ofMillis(1).toNanos());
            client.lookup(IP);
            assertEquals(2, http.calls.size(), "asked again once its life ends");
        }
    }

    @ParameterizedTest
    @MethodSource("lives")
    void aBatchEntryStaysCachedForItsLife(String flag, boolean value, int ttl, int life) {
        AtomicLong now = new AtomicLong();
        StubHttpClient http = StubHttpClient.of(Map.of(IP, StubHttpClient.Route.ok(body(flag, value))));
        try (VPNDetection client = client(http, now, ttl)) {
            assertTrue(client.lookupBatch(List.of(IP)).get(IP).result().isPresent());
            now.addAndGet(Duration.ofSeconds(life).minusMillis(1).toNanos());
            client.lookup(IP);
            assertEquals(1, http.calls.size(), "still cached a millisecond before its life ends");

            now.addAndGet(Duration.ofMillis(1).toNanos());
            client.lookup(IP);
            assertEquals(2, http.calls.size(), "asked again once its life ends");
            assertTrue(http.calls.get(1).endsWith("/" + IP), "the second request is the lookup");
        }
    }

    // A plain answer with neither flag, then the one under test set.
    private static String body(String flag, boolean value) {
        return flag == null
                ? "{\"ip\":\"" + IP + "\",\"is_vpn\":false}"
                : "{\"ip\":\"" + IP + "\",\"is_vpn\":false,\"" + flag + "\":" + value + "}";
    }

    private static VPNDetection client(StubHttpClient http, AtomicLong now, int ttl) {
        Ticker ticker = now::get;
        return VPNDetection.builder()
                .httpClient(http)
                .cacheTtl(Duration.ofSeconds(ttl))
                .cacheTicker(ticker)
                .build();
    }
}
