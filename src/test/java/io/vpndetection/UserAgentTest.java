package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.vpndetection.model.UserAgentVerdict;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * The user agent a lookup, {@code myIp} and a batch send, against a real local origin that answers
 * each agent with its verdict, so what reached the wire is asserted as the origin read it.
 */
class UserAgentTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String GOOGLEBOT =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

    private HttpServer server;
    // Each request's raw query (null for none) and, for a batch, its body, in arrival order.
    private final List<String> queries = Collections.synchronizedList(new ArrayList<>());
    private final List<JsonNode> batches = Collections.synchronizedList(new ArrayList<>());
    private volatile CountDownLatch hold;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::answer);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void answer(HttpExchange exchange) throws IOException {
        String body;
        try {
            if (hold != null) {
                hold.await(10, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if ("POST".equals(exchange.getRequestMethod())) {
            JsonNode sent = MAPPER.readTree(exchange.getRequestBody());
            batches.add(sent);
            queries.add(exchange.getRequestURI().getRawQuery());
            ObjectNode results = MAPPER.createObjectNode();
            for (JsonNode ip : sent.get("ips")) {
                JsonNode agent = sent.path("user_agents").get(ip.asText());
                results.set(ip.asText(), answerFor(ip.asText(), agent == null ? null : agent.asText()));
            }
            ObjectNode out = MAPPER.createObjectNode();
            out.set("results", results);
            out.set("errors", MAPPER.createObjectNode());
            body = out.toString();
        } else {
            String raw = exchange.getRequestURI().getRawQuery();
            queries.add(raw);
            String agent = null;
            if (raw != null && raw.startsWith("user_agent=")) {
                agent = URLDecoder.decode(raw.substring("user_agent=".length()), StandardCharsets.UTF_8);
            }
            String path = exchange.getRequestURI().getPath().substring(1);
            body = answerFor("myip".equals(path) ? "203.0.113.9" : path, agent).toString();
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    // The API's answer with every field: an agent sent comes back as its verdict.
    private static ObjectNode answerFor(String ip, String agent) {
        ObjectNode out = MAPPER.createObjectNode().put("ip", ip).put("is_vpn", false);
        if (agent != null) {
            out.putObject("user_agent").put("agent", agent).put("kind", "bot").put("verdict", "verified");
        }
        return out;
    }

    private VPNDetection.Builder client() {
        return VPNDetection.builder().apiKey("k").baseUrl("http://127.0.0.1:" + server.getAddress().getPort());
    }

    private static String agentOf(Result result) {
        return result.userAgent().map(UserAgentVerdict::getAgent).orElse(null);
    }

    @Test
    void aLookupSendsItsUserAgentAndReadsTheVerdict() {
        try (VPNDetection client = client().build()) {
            Result result = client.lookup("8.8.8.8", new LookupOptions().userAgent(GOOGLEBOT));
            assertEquals(GOOGLEBOT, agentOf(result));
            assertEquals(UserAgentVerdict.VerdictEnum.VERIFIED, result.userAgent().orElseThrow().getVerdict());
            assertEquals("bot", result.userAgent().orElseThrow().getKind());
        }
        assertEquals(1, queries.size());
        assertTrue(queries.get(0).startsWith("user_agent="), queries.get(0));
    }

    @Test
    void noUserAgentAndAnEmptyOneSendNoneAndReadNoVerdict() {
        try (VPNDetection client = client().cacheEnabled(false).build()) {
            assertEquals(Optional.empty(), client.lookup("8.8.8.8").userAgent());
            assertEquals(Optional.empty(), client.lookup("8.8.8.8", new LookupOptions().userAgent("")).userAgent());
            assertEquals(Optional.empty(), client.lookup("8.8.8.8", new LookupOptions().userAgent(null)).userAgent());
            assertEquals(Optional.empty(), client.myIp(new LookupOptions().userAgent("")).userAgent());
            client.lookupBatch(List.of("8.8.8.8", "1.1.1.1"), new BatchOptions().userAgent("")
                    .userAgents(Map.of("1.1.1.1", "")));
        }
        queries.forEach(query -> assertNull(query, "a query went out: " + query));
        assertEquals(List.of("ips"), fieldNames(batches.get(0)));
    }

    @Test
    void reservedCharactersArePercentEncodedOverUtf8() {
        String agent = "a b+c&d=e#f?g/h%i*j!k'l(m)n~o.p_q-r;s,t:u@v\"w中é";
        try (VPNDetection client = client().build()) {
            assertEquals(agent, agentOf(client.lookup("8.8.8.8", new LookupOptions().userAgent(agent))));
        }
        assertEquals("user_agent=a%20b%2Bc%26d%3De%23f%3Fg%2Fh%25i%2Aj%21k%27l%28m%29n~o.p_q-r%3Bs%2Ct%3Au%40v%22w"
                + "%E4%B8%AD%C3%A9", queries.get(0));
    }

    @Test
    void anAgentPastTheSpecsLengthIsSentWhole() {
        String agent = "x".repeat(5000);
        try (VPNDetection client = client().build()) {
            assertEquals(agent, agentOf(client.lookup("8.8.8.8", new LookupOptions().userAgent(agent))));
            assertEquals(agent, agentOf(client.lookupBatch(List.of("1.1.1.1", "9.9.9.9"),
                    new BatchOptions().userAgent(agent)).get("1.1.1.1").orElseThrow()));
        }
        assertEquals("user_agent=" + agent, queries.get(0));
        assertEquals(agent, batches.get(0).get("user_agents").get("9.9.9.9").asText());
    }

    @Test
    void myIpSendsItsUserAgentAndIsNeverCached() {
        try (VPNDetection client = client().build()) {
            assertEquals(GOOGLEBOT, agentOf(client.myIp(new LookupOptions().userAgent(GOOGLEBOT))));
            assertEquals(GOOGLEBOT, agentOf(client.myIp(new LookupOptions().userAgent(GOOGLEBOT))));
            assertEquals(Optional.empty(), client.myIp().userAgent());
        }
        assertEquals(3, queries.size());
    }

    @Test
    void aBogonIsAnsweredLocallyWithNoUserAgent() {
        try (VPNDetection client = client().build()) {
            Result result = client.lookup("10.0.0.1", new LookupOptions().userAgent(GOOGLEBOT));
            assertTrue(result.isBogon());
            assertEquals(Optional.empty(), result.userAgent());
            Result inBatch = client.lookupBatch(List.of("10.0.0.1", "192.168.0.1"),
                    new BatchOptions().userAgent(GOOGLEBOT)).get("10.0.0.1").orElseThrow();
            assertEquals(Optional.empty(), inBatch.userAgent());
        }
        assertEquals(0, queries.size(), "a bogon sends nothing");
    }

    @Test
    void theCacheHitsOnlyOnTheSameAddressAndAgent() {
        String[] agents = {null, GOOGLEBOT, GOOGLEBOT, "curl/8.0", null, "curl/8.0", ""};
        int[] sends = {1, 2, 2, 3, 3, 3, 3};
        try (VPNDetection client = client().build()) {
            for (int i = 0; i < agents.length; i++) {
                Result result = client.lookup("9.9.9.9", new LookupOptions().userAgent(agents[i]));
                assertEquals(sends[i], queries.size(), "step " + i);
                String want = agents[i] == null || agents[i].isEmpty() ? null : agents[i];
                assertEquals(want, agentOf(result), "step " + i);
            }
            // A batch reads the lookup's cache by the same pair, and fills it the same way.
            client.lookupBatch(List.of("9.9.9.9"), new BatchOptions().userAgent(GOOGLEBOT));
            assertEquals(3, queries.size());
            client.lookupBatch(List.of("9.9.9.9", "1.1.1.1"), new BatchOptions().userAgent("wget/1.0"));
            assertEquals(4, queries.size());
            assertEquals("wget/1.0", agentOf(client.lookup("1.1.1.1", new LookupOptions().userAgent("wget/1.0"))));
            assertEquals(4, queries.size());
        }
    }

    @Test
    void concurrentMissesShareARequestOnlyForTheSameAddressAndAgent() throws Exception {
        hold = new CountDownLatch(1);
        try (VPNDetection client = client().build()) {
            List<CompletableFuture<Result>> calls = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                calls.add(client.lookupAsync("9.9.9.9", new LookupOptions().userAgent(GOOGLEBOT)));
                calls.add(client.lookupAsync("9.9.9.9", new LookupOptions().userAgent("curl/8.0")));
                calls.add(client.lookupAsync("9.9.9.9"));
            }
            Thread.sleep(300);
            hold.countDown();
            for (int i = 0; i < calls.size(); i++) {
                String want = i % 3 == 0 ? GOOGLEBOT : i % 3 == 1 ? "curl/8.0" : null;
                assertEquals(want, agentOf(calls.get(i).get(10, TimeUnit.SECONDS)), "call " + i);
            }
        }
        assertEquals(3, queries.size());
    }

    @Test
    void aBatchSendsUserAgentsKeyedByTheAddressAsSent() {
        try (VPNDetection client = client().cacheEnabled(false).build()) {
            Map<String, BatchResult> out = client.lookupBatch(
                    List.of("1.1.1.1", "::ffff:9.9.9.9", "8.8.8.8", "2001:4860:4801:0010:0000:0000:0000:0001"),
                    new BatchOptions().userAgent(GOOGLEBOT).userAgents(Map.of(
                            "::ffff:9.9.9.9", "curl/8.0", "8.8.8.8", "",
                            "2001:4860:4801:0010:0000:0000:0000:0001", "wget/1.0")));
            assertEquals(GOOGLEBOT, agentOf(out.get("1.1.1.1").orElseThrow()));
            assertEquals("curl/8.0", agentOf(out.get("::ffff:9.9.9.9").orElseThrow()));
            assertNull(agentOf(out.get("8.8.8.8").orElseThrow()), "an empty agent is none, overriding userAgent");
            assertEquals("wget/1.0", agentOf(out.get("2001:4860:4801:0010:0000:0000:0000:0001").orElseThrow()));
        }
        assertEquals(1, batches.size());
        JsonNode agents = batches.get(0).get("user_agents");
        List<String> ips = new ArrayList<>();
        batches.get(0).get("ips").forEach(ip -> ips.add(ip.asText()));
        Map<String, String> sent = new HashMap<>();
        agents.fields().forEachRemaining(e -> sent.put(e.getKey(), e.getValue().asText()));
        assertEquals(Map.of("1.1.1.1", GOOGLEBOT, "9.9.9.9", "curl/8.0",
                "2001:4860:4801:0010:0000:0000:0000:0001", "wget/1.0"), sent);
        sent.keySet().forEach(ip -> assertTrue(ips.contains(ip), ip + " is not an address `ips` sends"));
    }

    @Test
    void userAgentsGoesOnlyWithAChunkWhoseAddressesCarryOne() {
        List<String> ips = new ArrayList<>();
        for (int i = 0; i < 1500; i++) {
            ips.add("11.0." + (i / 256) + "." + (i % 256));
        }
        try (VPNDetection client = client().cacheEnabled(false).build()) {
            client.lookupBatch(ips, new BatchOptions().concurrency(1)
                    .userAgents(Map.of(ips.get(1200), "curl/8.0")));
        }
        assertEquals(2, batches.size());
        assertEquals(List.of("ips"), fieldNames(batches.get(0)));
        assertEquals(List.of("ips", "user_agents"), fieldNames(batches.get(1)));
        assertEquals(1, batches.get(1).get("user_agents").size());
    }

    @Test
    void oneAddressPassedTwiceWithTwoAgentsIsAskedForEach() {
        try (VPNDetection client = client().build()) {
            Map<String, BatchResult> out = client.lookupBatch(List.of("8.8.8.8", "::ffff:8.8.8.8"),
                    new BatchOptions().userAgents(Map.of("8.8.8.8", GOOGLEBOT, "::ffff:8.8.8.8", "curl/8.0")));
            assertEquals(GOOGLEBOT, agentOf(out.get("8.8.8.8").orElseThrow()));
            assertEquals("curl/8.0", agentOf(out.get("::ffff:8.8.8.8").orElseThrow()));
        }
        assertEquals(2, batches.size());
        batches.forEach(batch -> assertEquals(1, batch.get("ips").size()));
    }

    @Test
    void anEntitlementRefusesAUserAgent() {
        try (VPNDetection client = client().build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class,
                    () -> client.myEntitlement(new LookupOptions().userAgent(GOOGLEBOT)));
            assertEquals(ErrorKind.BAD_REQUEST, err.kind());
        }
        assertEquals(0, queries.size());
    }

    @Test
    void anAnswerWithoutAVerdictReadsNone() {
        try (VPNDetection client = client().build()) {
            assertFalse(client.lookup("8.8.8.8").userAgent().isPresent());
        }
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> out = new ArrayList<>();
        node.fieldNames().forEachRemaining(out::add);
        return out;
    }
}
