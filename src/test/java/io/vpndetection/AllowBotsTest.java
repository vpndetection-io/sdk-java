package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vpndetection.middleware.Core;
import io.vpndetection.middleware.Lookup;
import io.vpndetection.middleware.Options;
import io.vpndetection.model.UserAgentVerdict;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The middleware's {@code allowBots}, from public peers only: a bogon peer is answered locally, so
 * it would pass every case vacuously. Each case asserts the agent that reached the origin, since a
 * stub answering a fixed verdict proves nothing about what was sent.
 */
class AllowBotsTest {
    private static final String GOOGLEBOT =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    private static final String GOOGLEBOT_SENT =
            "user_agent=Mozilla%2F5.0%20%28compatible%3B%20Googlebot%2F2.1%3B%20%2Bhttp%3A%2F%2Fwww.google.com"
                    + "%2Fbot.html%29";

    /** A request as the core sees it: the peer, and its User-Agent header or null. */
    private record Req(String ip, String userAgent) {}

    private static String answer(String ip, String verdict) {
        String agent = verdict == null ? ""
                : ", \"user_agent\": {\"agent\": \"Googlebot\", \"kind\": \"bot\", \"verdict\": \"" + verdict + "\"}";
        return "{\"ip\": \"" + ip + "\", \"is_vpn\": false, \"is_bot\": true" + agent + "}";
    }

    // 66.249.66.1 verified, 98.97.1.1 spoofed, 45.83.91.1 not_bot, 203.0.114.7 with no verdict.
    private static StubHttpClient origin() {
        return StubHttpClient.of(Map.of(
                "66.249.66.1", StubHttpClient.Route.ok(answer("66.249.66.1", "verified")),
                "98.97.1.1", StubHttpClient.Route.ok(answer("98.97.1.1", "spoofed")),
                "45.83.91.1", StubHttpClient.Route.ok(answer("45.83.91.1", "not_bot")),
                "203.0.114.7", StubHttpClient.Route.ok(answer("203.0.114.7", null))));
    }

    private static Core<Req> core(StubHttpClient http, Options<Req> options) {
        VPNDetection client = VPNDetection.builder().httpClient(http).build();
        return new Core<>(options.client(client), Req::ip, Req::userAgent);
    }

    private static String query(StubHttpClient http, int call) {
        return URI.create(http.calls.get(call)).getRawQuery();
    }

    @Test
    void offByDefaultItSendsNoAgentAndAVerifiedCrawlerIsRefused() {
        StubHttpClient http = origin();
        Lookup lookup = core(http, new Options<Req>().blockCondition(Map.of("is_bot", true)))
                .evaluate(new Req("66.249.66.1", GOOGLEBOT));
        assertTrue(lookup.isBlocked());
        assertEquals(null, query(http, 0));
    }

    @Test
    void onAVerifiedCrawlerPassesAConditionItMeetsWithItsAnswerAttached() {
        StubHttpClient http = origin();
        Lookup lookup = core(http, new Options<Req>().allowBots(true).blockCondition(Map.of("is_bot", true)))
                .evaluate(new Req("66.249.66.1", GOOGLEBOT));
        assertFalse(lookup.isBlocked());
        Result result = lookup.result().orElseThrow();
        assertEquals(UserAgentVerdict.VerdictEnum.VERIFIED, result.userAgent().orElseThrow().getVerdict());
        assertEquals(GOOGLEBOT_SENT, query(http, 0), "the request's own agent reached the origin");
    }

    @Test
    void onASpoofedOrNotBotAnswerIsStillRefused() {
        StubHttpClient http = origin();
        Core<Req> core = core(http, new Options<Req>().allowBots(true).blockCondition(Map.of("is_bot", true)));
        assertTrue(core.evaluate(new Req("98.97.1.1", GOOGLEBOT)).isBlocked());
        assertTrue(core.evaluate(new Req("45.83.91.1", GOOGLEBOT)).isBlocked());
        assertEquals(GOOGLEBOT_SENT, query(http, 0));
        assertEquals(GOOGLEBOT_SENT, query(http, 1));
    }

    @Test
    void aConditionOnTheVerdictRefusesAForgedCrawlerOnlyWithAllowBotsOn() {
        Map<String, Object> forged = Map.of("user_agent", Map.of("verdict", "spoofed"));
        StubHttpClient http = origin();
        Core<Req> on = core(http, new Options<Req>().allowBots(true).blockCondition(forged));
        assertTrue(on.evaluate(new Req("98.97.1.1", GOOGLEBOT)).isBlocked());
        assertFalse(on.evaluate(new Req("66.249.66.1", GOOGLEBOT)).isBlocked());

        StubHttpClient offHttp = StubHttpClient.of(Map.of(
                "98.97.1.1", StubHttpClient.Route.ok(answer("98.97.1.1", null))));
        List<String> warnings = new ArrayList<>();
        Core<Req> off = core(offHttp, new Options<Req>().blockCondition(forged).onWarn(warnings::add));
        assertFalse(off.evaluate(new Req("98.97.1.1", GOOGLEBOT)).isBlocked());
        assertEquals(null, query(offHttp, 0));
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("user_agent"), warnings.get(0));
    }

    @Test
    void anAbsentOrEmptyHeaderSendsNone() {
        StubHttpClient http = origin();
        Core<Req> core = core(http, new Options<Req>().allowBots(true).blockCondition(Map.of("is_bot", true))
                .onMissingField(Options.OnMissingField.THROW));
        assertTrue(core.evaluate(new Req("203.0.114.7", null)).isBlocked());
        assertTrue(core.evaluate(new Req("45.83.91.1", "")).isBlocked());
        assertEquals(null, query(http, 0));
        assertEquals(null, query(http, 1));
    }

    @Test
    void aSentAgentWithNoVerdictInAServedAnswerIsReportedOnce() {
        StubHttpClient http = origin();
        List<String> warnings = new ArrayList<>();
        Core<Req> core = core(http, new Options<Req>().allowBots(true).onWarn(warnings::add));
        Lookup first = core.evaluate(new Req("203.0.114.7", GOOGLEBOT));
        core.evaluate(new Req("203.0.114.7", "curl/8.0"));
        core.evaluate(new Req("66.249.66.1", GOOGLEBOT));
        assertFalse(first.isBlocked());
        assertTrue(first.result().isPresent());
        assertEquals(1, warnings.size(), String.valueOf(warnings));
        assertTrue(warnings.get(0).contains("user_agent"), warnings.get(0));
        assertEquals(GOOGLEBOT_SENT, query(http, 0));

        Core<Req> throwing = core(origin(), new Options<Req>().allowBots(true)
                .onMissingField(Options.OnMissingField.THROW));
        assertThrows(IllegalStateException.class, () -> throwing.evaluate(new Req("203.0.114.7", GOOGLEBOT)));

        List<String> ignored = new ArrayList<>();
        core(origin(), new Options<Req>().allowBots(true).onMissingField(Options.OnMissingField.IGNORE)
                .onWarn(ignored::add)).evaluate(new Req("203.0.114.7", GOOGLEBOT));
        assertEquals(List.of(), ignored);
    }

    @Test
    void aBogonPeerSendsNothingAndIsNotReported() {
        StubHttpClient http = origin();
        List<String> warnings = new ArrayList<>();
        Core<Req> core = core(http, new Options<Req>().allowBots(true).onMissingField(Options.OnMissingField.THROW)
                .onWarn(warnings::add));
        Lookup lookup = core.evaluate(new Req("10.0.0.1", GOOGLEBOT));
        assertTrue(lookup.result().orElseThrow().isBogon());
        assertEquals(0, http.calls.size());
        warnings.forEach(w -> assertFalse(w.contains("user_agent"), w));
    }

    @Test
    void allowBotsWithoutAHeaderReaderIsRefusedAtConstruction() {
        Options<Req> options = new Options<Req>().allowBots(true).client(VPNDetection.create());
        assertThrows(IllegalArgumentException.class, () -> new Core<>(options, Req::ip));
    }
}
