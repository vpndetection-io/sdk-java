package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vpndetection.middleware.Core;
import io.vpndetection.middleware.Lookup;
import io.vpndetection.middleware.Options;
import io.vpndetection.model.UserAgentVerdict;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The middleware's {@code allowBots}: a crawler's agent sent with the lookup, at most four an
 * address, and a verified crawler let through. Every request comes from a public peer, since a
 * bogon peer is answered locally and would pass every case vacuously. Each case asserts the agent
 * that reached the origin, since a stub answering a fixed verdict proves nothing about what was sent.
 */
class AllowBotsTest {
    private static final String GOOGLEBOT =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    private static final String CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            + "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36";
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

    private static String crawler(int n) {
        return "Mozilla/5.0 (compatible; Examplebot/" + n + ".0)";
    }

    // Any address, answering `verdict` to any agent that arrives (none to a lookup without one), and
    // `bot` as the answer's own say on the address when given.
    private static StubHttpClient anyOrigin(String verdict, String bot) {
        StubHttpClient[] self = new StubHttpClient[1];
        self[0] = StubHttpClient.responding(ip -> {
            boolean sent = sentAgent(self[0], self[0].calls.size() - 1) != null;
            return StubHttpClient.Route.ok("{\"ip\": \"" + ip + "\", \"is_vpn\": false, \"is_bot\": true"
                    + (bot == null ? "" : ", \"bot\": " + bot)
                    + (sent ? ", \"user_agent\": {\"agent\": \"Googlebot\", \"kind\": \"bot\", "
                            + "\"verdict\": \"" + verdict + "\"}" : "") + "}");
        });
        return self[0];
    }

    // The agent a call carried, null for an address-only lookup.
    private static String sentAgent(StubHttpClient http, int call) {
        String query = query(http, call);
        if (query == null) {
            return null;
        }
        String prefix = "user_agent=";
        assertTrue(query.startsWith(prefix), query);
        return URLDecoder.decode(query.substring(prefix.length()), StandardCharsets.UTF_8);
    }

    private static List<String> agents(StubHttpClient http) {
        List<String> sent = new ArrayList<>();
        for (int call = 0; call < http.calls.size(); call++) {
            sent.add(sentAgent(http, call));
        }
        return sent;
    }

    private static Core<Req> core(StubHttpClient http, Options<Req> options) {
        VPNDetection client = VPNDetection.builder().httpClient(http).build();
        return new Core<>(options.client(client), Req::ip, Req::userAgent);
    }

    // The bot-refusing condition with allowBots on, over an uncached client: every request reaches
    // the origin, so what arrived is what the core sent.
    private static Core<Req> refusingBots(StubHttpClient http) {
        VPNDetection client = VPNDetection.builder().httpClient(http).cacheEnabled(false).build();
        Options<Req> options = new Options<Req>().allowBots(true).blockCondition(Map.of("is_bot", true));
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
        core.evaluate(new Req("203.0.114.7", GOOGLEBOT));
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
    void onlyAnAgentNamingACrawlerIsSentAsTheCorpusSays() throws IOException {
        JsonNode corpus = new ObjectMapper().readTree(Path.of("testdata", "testdata.json").toFile())
                .get("crawlerAgents");
        assertTrue(corpus.get("crawlers").size() > 0 && corpus.get("others").size() > 0);
        for (JsonNode ua : corpus.get("crawlers")) {
            assertTrue(Core.namesCrawler(ua.asText()), ua.asText());
        }
        for (JsonNode ua : corpus.get("others")) {
            assertFalse(Core.namesCrawler(ua.asText()), ua.asText());
        }
        for (JsonNode term : corpus.get("terms")) {
            String inText = "x " + term.asText().toUpperCase(Locale.ROOT) + " y";
            assertTrue(Core.namesCrawler(inText), inText);
        }
        assertTrue(Core.namesCrawler("BARKROWLER"));
        assertFalse(Core.namesCrawler("BAR" + (char) 0x212A + "ROWLER"), "A to Z only, no Unicode lowercase");

        StubHttpClient http = anyOrigin("not_bot", null);
        Lookup lookup = refusingBots(http).evaluate(new Req("66.249.66.1", CHROME));
        assertEquals(Arrays.asList((String) null), agents(http), "a browser's agent stays off the lookup");
        assertTrue(lookup.isBlocked());
    }

    @Test
    void oneAddressIsLookedUpWithAtMostFourCrawlerAgentsAndNonePassesPastThem() {
        assertEquals(4, Core.MAX_AGENTS_PER_ADDRESS);
        StubHttpClient http = anyOrigin("verified", null);
        Core<Req> core = refusingBots(http);
        for (int n = 1; n <= 4; n++) {
            assertFalse(core.evaluate(new Req("66.249.66.1", crawler(n))).isBlocked(), "agent " + n);
        }
        Lookup past = core.evaluate(new Req("66.249.66.1", crawler(5)));
        assertTrue(past.isBlocked(), "an agent past the bound is never let through as verified");
        assertTrue(past.result().orElseThrow().userAgent().isEmpty());
        assertFalse(core.evaluate(new Req("66.249.66.1", crawler(1))).isBlocked(), "a known agent is sent");
        assertEquals(Arrays.asList(crawler(1), crawler(2), crawler(3), crawler(4), null, crawler(1)),
                agents(http));

        assertFalse(core.evaluate(new Req("66.249.66.2", crawler(5))).isBlocked(), "another address");
        assertEquals(crawler(5), sentAgent(http, http.calls.size() - 1));
    }

    @Test
    void pastTheBoundAnAddressItsOperatorVouchesForStillPasses() {
        StubHttpClient http = anyOrigin("verified", "{\"verified\": true}");
        Core<Req> core = refusingBots(http);
        for (int n = 1; n <= 5; n++) {
            assertFalse(core.evaluate(new Req("66.249.66.1", crawler(n))).isBlocked(), "agent " + n);
        }
        assertEquals(null, sentAgent(http, http.calls.size() - 1));
        assertTrue(core.evaluate(new Req("66.249.66.1", CHROME)).isBlocked(),
                "a browser on that address is judged as the condition says");
    }

    @Test
    void aConditionOnTheVerdictIsNoPlanGapForARequestThatSentNoAgent() {
        Map<String, Object> forged = Map.of("user_agent", Map.of("verdict", "spoofed"));
        for (String header : new String[] {CHROME, null}) {
            StubHttpClient http = anyOrigin("spoofed", null);
            List<String> warnings = new ArrayList<>();
            Core<Req> core = core(http, new Options<Req>().allowBots(true).blockCondition(forged)
                    .onMissingField(Options.OnMissingField.THROW).onWarn(warnings::add));
            assertFalse(core.evaluate(new Req("66.249.66.1", header)).isBlocked(), String.valueOf(header));
            assertEquals(Arrays.asList((String) null), agents(http));
            assertEquals(List.of(), warnings);
        }

        StubHttpClient http = anyOrigin("spoofed", null);
        Core<Req> past = core(http, new Options<Req>().allowBots(true).blockCondition(forged)
                .onMissingField(Options.OnMissingField.THROW));
        for (int n = 1; n <= 4; n++) {
            assertTrue(past.evaluate(new Req("66.249.66.1", crawler(n))).isBlocked(), "agent " + n);
        }
        assertFalse(past.evaluate(new Req("66.249.66.1", crawler(5))).isBlocked(), "past the bound, no gap either");
        assertEquals(null, sentAgent(http, http.calls.size() - 1));

        StubHttpClient offHttp = anyOrigin("spoofed", null);
        List<String> warned = new ArrayList<>();
        core(offHttp, new Options<Req>().blockCondition(forged).onWarn(warned::add))
                .evaluate(new Req("66.249.66.1", CHROME));
        assertEquals(1, warned.size(), "off, a condition on the verdict can never match, and says so");
    }

    @Test
    void everyOtherMemberIsStillReportedForARequestThatSentNoAgent() {
        StubHttpClient http = anyOrigin("spoofed", null);
        List<String> warnings = new ArrayList<>();
        core(http, new Options<Req>().allowBots(true)
                .blockCondition(Map.of("user_agent", Map.of("verdict", "spoofed"), "is_tor", true))
                .onWarn(warnings::add)).evaluate(new Req("66.249.66.1", CHROME));
        assertEquals(Arrays.asList((String) null), agents(http));
        assertEquals(1, warnings.size(), String.valueOf(warnings));
        assertTrue(warnings.get(0).contains("is_tor") && !warnings.get(0).contains("user_agent"), warnings.get(0));
    }

    @Test
    void aVerdictConditionIsStillReportedWhenTheAgentWasSentAndTheAnswerLacksIt() {
        StubHttpClient http = origin();
        List<String> warnings = new ArrayList<>();
        core(http, new Options<Req>().allowBots(true)
                .blockCondition(Map.of("user_agent", Map.of("verdict", "spoofed"))).onWarn(warnings::add))
                .evaluate(new Req("203.0.114.7", GOOGLEBOT));
        assertEquals(GOOGLEBOT_SENT, query(http, 0));
        assertTrue(warnings.stream().anyMatch(w -> w.startsWith("blockCondition names user_agent")),
                String.valueOf(warnings));
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
