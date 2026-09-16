package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.OauthStub.Answer;
import io.vpndetection.OauthStub.Sent;
import io.vpndetection.internal.ApiClient;
import io.vpndetection.model.DeviceAuthorization;
import io.vpndetection.model.OauthMetadata;
import io.vpndetection.model.TokenResponse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Function;

/**
 * The {@code oauth} accessor against the corpus's {@code oauth} vectors, plus what the corpus cannot
 * say: timeouts, interruption, and a 2xx that is not the documented shape. The deferred
 * authorization-code vectors are never read.
 */
class OauthTest {
    private static final ObjectMapper MAPPER = ApiClient.createDefaultObjectMapper();
    private static final String CLIENT_ID = "sdk-java-test";
    // Longer than any poll here takes on the fake clock, short enough that a loop fails the test.
    private static final Duration OUTSIDE = Duration.ofSeconds(10);
    // The corpus metadata still carries this; the published spec no longer advertises it.
    private static final String UNPUBLISHED_MEMBER = "client_id_metadata_document_supported";
    private static final Map<String, Class<?>> TYPES = Map.of(
            "oauth", OauthException.class,
            "accessDenied", OauthAccessDeniedException.class,
            "expiredToken", OauthExpiredTokenException.class,
            "client", VPNDetectionException.class);

    private static JsonNode oauth;

    @BeforeAll
    static void loadCorpus() throws IOException {
        oauth = MAPPER.readTree(Path.of("testdata", "testdata.json").toFile()).get("oauth");
    }

    @Test
    void everyOperationRequestsItsEndpoint() {
        JsonNode endpoints = oauth.get("endpoints");
        OauthStub http = OauthStub.answering(success("metadata"));
        // One trailing slash on the base URL is dropped, not doubled into the path.
        try (VPNDetection client = clientOn(http).baseUrl("http://oauth.test/").build()) {
            client.oauth().metadata();
        }
        assertEndpoint(endpoints.get("metadata"), only(http), "metadata");

        for (JsonNode c : oauth.get("forms").get("cases")) {
            String name = c.get("name").asText();
            OauthStub each = OauthStub.answering(success(c.get("operation").asText()));
            try (VPNDetection client = clientOn(each).baseUrl("http://oauth.test/").build()) {
                invoke(client.oauth(), c.get("operation").asText(), c.get("args"));
            }
            assertEndpoint(endpoints.get(c.get("endpoint").asText()), only(each), name);
        }
    }

    // Every case runs on a client with NO key, which is what a device sign-in starts from.
    @Test
    void everyFormCarriesExactlyItsFields() {
        JsonNode forms = oauth.get("forms");
        for (JsonNode c : forms.get("cases")) {
            String name = c.get("name").asText();
            OauthStub http = OauthStub.answering(success(c.get("operation").asText()));
            try (VPNDetection client = clientOn(http).build()) {
                invoke(client.oauth(), c.get("operation").asText(), c.get("args"));
            }
            Sent sent = only(http);
            assertTrue(sent.headers().firstValue("content-type").orElse("")
                    .startsWith(forms.get("contentType").asText()), name + ": content type");
            Map<String, String> want = new HashMap<>();
            c.get("fields").fields().forEachRemaining(f -> want.put(f.getKey(), f.getValue().asText()));
            assertEquals(want, OauthStub.formFields(sent.body()), name + ": fields");
        }
    }

    @Test
    void anOptionLeftEmptyIsLeftOut() {
        OauthStub http = OauthStub.answering(success("deviceAuthorization"));
        try (VPNDetection client = clientOn(http).build()) {
            client.oauth().deviceAuthorization(CLIENT_ID,
                    new DeviceAuthorizationOptions().scope("").resource(""));
        }
        assertEquals(Map.of("client_id", CLIENT_ID), OauthStub.formFields(only(http).body()));
    }

    @Test
    void noOauthRequestCarriesTheApiKey() {
        JsonNode rule = oauth.get("noCredential");
        String key = rule.get("apiKey").asText();
        OauthStub http = OauthStub.answering(success("metadata"), success("deviceAuthorization"),
                success("exchangeDeviceCode"), success("exchangeRefreshToken"), success("revoke"),
                success("exchangeDeviceCode"), Answer.of(200, "{\"ip\": \"1.1.1.1\", \"is_vpn\": false}"));
        try (VPNDetection client = clientOn(http).apiKey(key).build()) {
            OauthApi api = client.oauth().ticking(new FakeTicker());
            api.metadata();
            api.deviceAuthorization(CLIENT_ID, new DeviceAuthorizationOptions().scope("account.read"));
            api.exchangeDeviceCode(CLIENT_ID, "mo_dc_nokey");
            api.exchangeRefreshToken(CLIENT_ID, "mo_rt_nokey");
            api.revoke(CLIENT_ID, "mo_rt_nokey");
            assertTimeoutPreemptively(OUTSIDE, () -> api.pollDeviceToken(CLIENT_ID, device(1, 900)));
            // The same client does send the key where it belongs, so the checks below are not vacuous.
            client.lookup("1.1.1.1");
        }

        assertEquals(7, http.sent.size());
        List<Sent> oauthRequests = http.sent.subList(0, 6);
        for (Sent sent : oauthRequests) {
            String where = sent.method() + " " + sent.uri();
            for (JsonNode header : rule.get("forbiddenHeaders")) {
                assertTrue(sent.headers().firstValue(header.asText()).isEmpty(), where + " carried " + header);
            }
            for (String query : queryKeys(sent)) {
                for (JsonNode forbidden : rule.get("forbiddenQuery")) {
                    assertFalse(query.equalsIgnoreCase(forbidden.asText()), where + " carried ?" + query);
                }
            }
            assertFalse(sent.uri().toString().contains(key), where + ": the key is in the URL");
            sent.headers().map().forEach((name, values) -> values.forEach(
                    value -> assertFalse(value.contains(key), where + ": the key is in " + name)));
            assertFalse(sent.body() != null && sent.body().contains(key), where + ": the key is in the body");
        }
        assertEquals(Optional.of("Bearer " + key), http.sent.get(6).headers().firstValue("authorization"));
    }

    @Test
    void aServedAnswerKeepsAbsentMembersAbsent() {
        JsonNode responses = oauth.get("responses");
        for (JsonNode c : responses.get("metadata")) {
            OauthStub http = OauthStub.answering(answer(c));
            try (VPNDetection client = clientOn(http).build()) {
                OauthMetadata got = client.oauth().metadata();
                assertMembers(c, wire -> metadataMember(got, wire));
            }
        }
        for (JsonNode c : responses.get("deviceAuthorization")) {
            OauthStub http = OauthStub.answering(answer(c));
            try (VPNDetection client = clientOn(http).build()) {
                DeviceAuthorization got = client.oauth().deviceAuthorization(CLIENT_ID);
                assertMembers(c, wire -> deviceMember(got, wire));
            }
        }
        for (JsonNode c : responses.get("token")) {
            OauthStub http = OauthStub.answering(answer(c));
            try (VPNDetection client = clientOn(http).build()) {
                TokenResponse got = client.oauth().exchangeDeviceCode(CLIENT_ID, "mo_dc_decode");
                assertMembers(c, wire -> tokenMember(got, wire));
            }
        }
        for (JsonNode c : responses.get("revoke")) {
            OauthStub http = OauthStub.answering(answer(c));
            try (VPNDetection client = clientOn(http).build()) {
                client.oauth().revoke(CLIENT_ID, "mo_rt_decode");
            }
            assertEquals(1, http.sent.size(), c.get("name").asText());
        }
    }

    // The generated model starts a list empty; a list the server left out must still read as absent.
    @Test
    void aMetadataListTheServerLeftOutIsAbsentNotEmpty() {
        OauthStub http = OauthStub.answering(Answer.of(200, "{\"issuer\": \"https://api.vpndetection.io\", "
                + "\"authorization_endpoint\": \"https://api.vpndetection.io/oauth/authorize\", "
                + "\"token_endpoint\": \"https://api.vpndetection.io/oauth/token\"}"));
        try (VPNDetection client = clientOn(http).build()) {
            OauthMetadata got = client.oauth().metadata();
            for (String wire : List.of("device_authorization_endpoint", "revocation_endpoint",
                    "scopes_supported", "response_types_supported", "grant_types_supported",
                    "code_challenge_methods_supported", "token_endpoint_auth_methods_supported",
                    "authorization_response_iss_parameter_supported", "service_documentation")) {
                assertNull(metadataMember(got, wire), wire + " must be absent");
            }
        }
    }

    @Test
    void aRefusalIsAnOauthErrorOnlyWhenA4xxNamesOne() {
        for (JsonNode c : oauth.get("errors").get("cases")) {
            String name = c.get("name").asText();
            OauthStub http = OauthStub.answering(answer(c));
            try (VPNDetection client = clientOn(http).build()) {
                VPNDetectionException e = assertThrows(VPNDetectionException.class,
                        () -> client.oauth().exchangeDeviceCode(CLIENT_ID, "mo_dc_errors"), name);
                JsonNode expect = c.get("expect");
                assertError(name, expect.get("type").asText(), expect, e);
            }
        }
    }

    @Test
    void onlyTheOperationsThatSpendNothingAreRetried() {
        for (JsonNode c : oauth.get("retries").get("cases")) {
            String name = c.get("name").asText();
            JsonNode expect = c.get("expect");
            OauthStub http = OauthStub.answering(answers(c.get("responses")));
            VPNDetectionException failure = null;
            try (VPNDetection client = clientOn(http).build()) {
                invoke(client.oauth(), c.get("operation").asText(), c.get("args"));
            } catch (VPNDetectionException e) {
                failure = e;
            }
            // First, so a retry is reported as one rather than as whatever the extra request drew.
            assertEquals(expect.get("requests").asInt(), http.sent.size(), name + ": requests");
            String outcome = expect.get("outcome").asText();
            if (outcome.equals("ok")) {
                assertNull(failure, name + ": " + failure);
            } else {
                assertError(name, outcome, expect, assertInstanceOf(VPNDetectionException.class, failure, name));
            }
        }
    }

    @Test
    void thePollWaitsWidensAndEndsAsTheCorpusSays() throws JsonProcessingException {
        for (JsonNode c : oauth.get("poll").get("cases")) {
            String name = c.get("name").asText();
            JsonNode expect = c.get("expect");
            DeviceAuthorization device = MAPPER.treeToValue(c.get("device"), DeviceAuthorization.class);
            OauthStub http = OauthStub.answering(answers(c.get("responses")));
            FakeTicker ticker = new FakeTicker();
            Object ended;
            try (VPNDetection client = clientOn(http).build()) {
                OauthApi api = client.oauth().ticking(ticker);
                ended = assertTimeoutPreemptively(OUTSIDE, () -> {
                    try {
                        return api.pollDeviceToken(c.get("clientId").asText(), device);
                    } catch (VPNDetectionException e) {
                        return e;
                    }
                }, name + ": the poll never ended");
            }

            String outcome = expect.get("outcome").asText();
            if (outcome.equals("token")) {
                TokenResponse token = assertInstanceOf(TokenResponse.class, ended, name);
                if (expect.has("token")) {
                    expect.get("token").fields().forEachRemaining(
                            f -> assertEquals(value(f.getValue()), tokenMember(token, f.getKey()), name));
                }
            } else {
                assertError(name, outcome, expect, assertInstanceOf(VPNDetectionException.class, ended, name));
            }
            assertEquals(expect.get("requests").asInt(), http.sent.size(), name + ": requests");
            Map<String, String> form = Map.of("grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code", device.getDeviceCode(), "client_id", c.get("clientId").asText());
            for (Sent sent : http.sent) {
                assertEquals("/oauth/token", sent.uri().getPath(), name);
                assertEquals(form, OauthStub.formFields(sent.body()), name);
            }
            List<Long> waits = new ArrayList<>();
            expect.get("waits").forEach(w -> waits.add(w.asLong()));
            assertEquals(waits, ticker.waits, name + ": waits, in seconds");
        }
    }

    // On the real clock: the first wait is 5 s, so a poll that ignored the interrupt would still be
    // sleeping at the assertion.
    @Test
    void interruptingAPollEndsItAtOnceAsANetworkFailure() throws InterruptedException {
        OauthStub http = OauthStub.answering(Answer.of(400, "{\"error\": \"authorization_pending\"}"));
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        AtomicBoolean flagRestored = new AtomicBoolean();
        CountDownLatch ended = new CountDownLatch(1);
        try (VPNDetection client = clientOn(http).build()) {
            Thread poller = new Thread(() -> {
                try {
                    client.oauth().pollDeviceToken(CLIENT_ID, device(5, 900));
                } catch (Throwable e) {
                    thrown.set(e);
                    flagRestored.set(Thread.currentThread().isInterrupted());
                } finally {
                    ended.countDown();
                }
            }, "poller");
            poller.setDaemon(true);
            poller.start();
            Thread.sleep(200);
            poller.interrupt();

            assertTrue(ended.await(1, TimeUnit.SECONDS), "the poll outlived its interrupt");
        }
        VPNDetectionException e = assertInstanceOf(VPNDetectionException.class, thrown.get());
        assertEquals(ErrorKind.NETWORK, e.kind());
        assertTrue(flagRestored.get(), "the interrupt flag was swallowed");
        assertEquals(0, http.sent.size(), "a request went out after the interrupt");
    }

    @Test
    void aPerCallTimeoutBelowTheClientsBoundsEveryOauthRequest() {
        OauthStub http = OauthStub.hanging();
        Duration fast = Duration.ofMillis(200);
        OauthOptions options = new OauthOptions().requestTimeout(fast);
        try (VPNDetection client = clientOn(http).retries(0).requestTimeout(Duration.ofSeconds(10)).build()) {
            OauthApi api = client.oauth().ticking(new FakeTicker());
            assertTimesOut(() -> api.metadata(options));
            assertTimesOut(() -> api.deviceAuthorization(CLIENT_ID,
                    new DeviceAuthorizationOptions().requestTimeout(fast)));
            assertTimesOut(() -> api.exchangeDeviceCode(CLIENT_ID, "mo_dc_slow", options));
            assertTimesOut(() -> api.exchangeRefreshToken(CLIENT_ID, "mo_rt_slow", options));
            assertTimesOut(() -> api.revoke(CLIENT_ID, "mo_rt_slow", options));
            assertTimesOut(() -> api.pollDeviceToken(CLIENT_ID, device(1, 900), options));
        }
        assertEquals(6, http.sent.size());
    }

    @Test
    void a2xxThatIsNotTheDocumentedShapeIsTheOrdinaryError() {
        List<String> bodies = List.of("not json", "[]", "",
                "{\"token_type\": \"Bearer\", \"expires_in\": 3600}",
                "{\"access_token\": {\"not\": \"a string\"}, \"token_type\": \"Bearer\", \"expires_in\": 1}");
        for (String body : bodies) {
            OauthStub http = OauthStub.answering(Answer.of(200, body));
            try (VPNDetection client = clientOn(http).build()) {
                VPNDetectionException e = assertThrows(VPNDetectionException.class,
                        () -> client.oauth().exchangeDeviceCode(CLIENT_ID, "mo_dc_shape"), body);
                assertEquals(VPNDetectionException.class, e.getClass(), body);
                assertEquals(ErrorKind.SERVER_ERROR, e.kind(), body);
                assertEquals(Optional.of(200), e.statusCode(), body);
            }
            assertEquals(1, http.sent.size(), body);
        }

        OauthStub http = OauthStub.answering(Answer.of(200, "{\"issuer\": \"https://api.vpndetection.io\"}"));
        try (VPNDetection client = clientOn(http).retries(0).build()) {
            VPNDetectionException e = assertThrows(VPNDetectionException.class, () -> client.oauth().metadata());
            assertEquals(VPNDetectionException.class, e.getClass());
            assertEquals("the answer carried no authorization_endpoint", e.getMessage());
        }
    }

    private static VPNDetection.Builder clientOn(OauthStub http) {
        return VPNDetection.builder().httpClient(http);
    }

    private static DeviceAuthorization device(int interval, int expiresIn) {
        return new DeviceAuthorization().deviceCode("mo_dc_test").userCode("BCDF-GHJK")
                .verificationUri("https://app.vpndetection.io/device").expiresIn(expiresIn).interval(interval);
    }

    // A 2xx each operation decodes, taken from the corpus's own first response case.
    private static Answer success(String operation) {
        JsonNode responses = oauth.get("responses");
        switch (operation) {
            case "metadata":
                return answer(responses.get("metadata").get(0));
            case "deviceAuthorization":
                return answer(responses.get("deviceAuthorization").get(0));
            case "exchangeDeviceCode":
            case "exchangeRefreshToken":
                return answer(responses.get("token").get(0));
            case "revoke":
                return answer(responses.get("revoke").get(0));
            default:
                throw new IllegalArgumentException("the corpus names an operation this SDK lacks: " + operation);
        }
    }

    // rawBody is sent verbatim, body as JSON.
    private static Answer answer(JsonNode response) {
        String body = response.has("rawBody")
                ? response.get("rawBody").asText()
                : response.get("body").toString();
        return Answer.of(response.get("status").asInt(), body);
    }

    private static List<Answer> answers(JsonNode responses) {
        List<Answer> out = new ArrayList<>();
        responses.forEach(r -> out.add(answer(r)));
        return out;
    }

    private static Object invoke(OauthApi api, String operation, JsonNode args) {
        switch (operation) {
            case "metadata":
                return api.metadata();
            case "deviceAuthorization":
                DeviceAuthorizationOptions options = new DeviceAuthorizationOptions();
                if (args.has("scope")) {
                    options.scope(args.get("scope").asText());
                }
                if (args.has("resource")) {
                    options.resource(args.get("resource").asText());
                }
                return api.deviceAuthorization(args.get("clientId").asText(), options);
            case "exchangeDeviceCode":
                return api.exchangeDeviceCode(args.get("clientId").asText(), args.get("deviceCode").asText());
            case "exchangeRefreshToken":
                return api.exchangeRefreshToken(args.get("clientId").asText(),
                        args.get("refreshToken").asText());
            case "revoke":
                api.revoke(args.get("clientId").asText(), args.get("token").asText());
                return null;
            default:
                throw new IllegalArgumentException("the corpus names an operation this SDK lacks: " + operation);
        }
    }

    private static Sent only(OauthStub http) {
        assertEquals(1, http.sent.size(), "requests");
        return http.sent.get(0);
    }

    private static void assertEndpoint(JsonNode endpoint, Sent sent, String name) {
        assertEquals(endpoint.get("method").asText(), sent.method(), name + ": method");
        assertEquals(endpoint.get("path").asText(), sent.uri().getPath(), name + ": path");
        assertNull(sent.uri().getQuery(), name + ": query");
    }

    // type is the corpus's: oauth, accessDenied, expiredToken or client, the last being the ordinary
    // error and never an OauthException.
    private static void assertError(String name, String type, JsonNode expect, VPNDetectionException e) {
        assertEquals(TYPES.get(type), e.getClass(), name + ": type, from " + e);
        if (expect.has("status")) {
            JsonNode status = expect.get("status");
            assertEquals(status.isNull() ? Optional.empty() : Optional.of(status.asInt()), e.statusCode(),
                    name + ": status");
        }
        if (expect.has("kind")) {
            assertEquals(expect.get("kind").asText(), e.kind().name().toLowerCase(Locale.ROOT), name + ": kind");
        }
        if (expect.has("retryable")) {
            assertEquals(expect.get("retryable").asBoolean(), e.retryable(), name + ": retryable");
        }
        if (type.equals("client")) {
            return;
        }
        OauthException refused = (OauthException) e;
        if (expect.has("errorCode")) {
            assertEquals(expect.get("errorCode").asText(), refused.errorCode(), name + ": errorCode");
        }
        if (expect.has("errorDescription")) {
            JsonNode description = expect.get("errorDescription");
            assertEquals(description.isNull() ? Optional.empty() : Optional.of(description.asText()),
                    refused.errorDescription(), name + ": errorDescription");
        }
        if (expect.has("message")) {
            assertEquals(expect.get("message").asText(), refused.getMessage(), name + ": message");
        }
    }

    private static void assertMembers(JsonNode c, Function<String, Object> member) {
        String name = c.get("name").asText();
        JsonNode expect = c.get("expect");
        expect.get("present").fields().forEachRemaining(f -> {
            if (!f.getKey().equals(UNPUBLISHED_MEMBER)) {
                assertEquals(value(f.getValue()), member.apply(f.getKey()), name + ": " + f.getKey());
            }
        });
        for (JsonNode absent : expect.get("absent")) {
            assertNull(member.apply(absent.asText()), name + ": " + absent.asText() + " must be ABSENT");
        }
    }

    private static void assertTimesOut(Runnable call) {
        long started = System.nanoTime();
        VPNDetectionException e = assertThrows(VPNDetectionException.class, call::run);
        long took = Duration.ofNanos(System.nanoTime() - started).toMillis();

        assertEquals(VPNDetectionException.class, e.getClass(), e.toString());
        assertEquals(ErrorKind.NETWORK, e.kind(), e.getMessage());
        assertTrue(e.retryable());
        assertTrue(took < 5000, "took " + took + "ms, past the per-call bound");
    }

    private static List<String> queryKeys(Sent sent) {
        String query = sent.uri().getRawQuery();
        List<String> keys = new ArrayList<>();
        if (query != null) {
            for (String pair : query.split("&")) {
                keys.add(URLDecoder.decode(pair.split("=", 2)[0], StandardCharsets.UTF_8));
            }
        }
        return keys;
    }

    // The corpus writes a member's value as JSON; the models surface strings, Integers, Booleans and
    // lists of strings.
    private static Object value(JsonNode node) {
        if (node.isTextual()) {
            return node.asText();
        }
        if (node.isBoolean()) {
            return node.asBoolean();
        }
        if (node.isInt()) {
            return node.asInt();
        }
        if (node.isArray()) {
            List<String> out = new ArrayList<>();
            node.forEach(item -> out.add(item.asText()));
            return out;
        }
        throw new IllegalArgumentException("no model member holds " + node);
    }

    private static Object metadataMember(OauthMetadata m, String wire) {
        switch (wire) {
            case "issuer":
                return m.getIssuer();
            case "authorization_endpoint":
                return m.getAuthorizationEndpoint();
            case "token_endpoint":
                return m.getTokenEndpoint();
            case "device_authorization_endpoint":
                return m.getDeviceAuthorizationEndpoint();
            case "revocation_endpoint":
                return m.getRevocationEndpoint();
            case "scopes_supported":
                return m.getScopesSupported();
            case "response_types_supported":
                return m.getResponseTypesSupported();
            case "grant_types_supported":
                return m.getGrantTypesSupported();
            case "code_challenge_methods_supported":
                return m.getCodeChallengeMethodsSupported();
            case "token_endpoint_auth_methods_supported":
                return m.getTokenEndpointAuthMethodsSupported();
            case "authorization_response_iss_parameter_supported":
                return m.getAuthorizationResponseIssParameterSupported();
            case "service_documentation":
                return m.getServiceDocumentation();
            default:
                throw new IllegalArgumentException("the corpus names a member this SDK lacks: " + wire);
        }
    }

    private static Object deviceMember(DeviceAuthorization d, String wire) {
        switch (wire) {
            case "device_code":
                return d.getDeviceCode();
            case "user_code":
                return d.getUserCode();
            case "verification_uri":
                return d.getVerificationUri();
            case "verification_uri_complete":
                return d.getVerificationUriComplete();
            case "expires_in":
                return d.getExpiresIn();
            case "interval":
                return d.getInterval();
            default:
                throw new IllegalArgumentException("the corpus names a member this SDK lacks: " + wire);
        }
    }

    private static Object tokenMember(TokenResponse t, String wire) {
        switch (wire) {
            case "access_token":
                return t.getAccessToken();
            case "token_type":
                return t.getTokenType();
            case "expires_in":
                return t.getExpiresIn();
            case "refresh_token":
                return t.getRefreshToken();
            case "scope":
                return t.getScope();
            case "apikey_id":
                return t.getApikeyId();
            case "apikey":
                return t.getApikey();
            default:
                throw new IllegalArgumentException("the corpus names a member this SDK lacks: " + wire);
        }
    }

    /**
     * A clock that moves only when the poll sleeps, keeping every sleep in seconds.
     *
     * <p>Bounded like the stub: past its cap a sleep or a clock read never returns, so a poll that
     * loops fails its test from outside rather than spinning.
     */
    static final class FakeTicker implements OauthApi.Ticker {
        private static final int CAP = OauthStub.CAP;

        final List<Long> waits = Collections.synchronizedList(new ArrayList<>());
        private final AtomicLong now = new AtomicLong();
        private final AtomicInteger reads = new AtomicInteger();

        @Override
        public long nanoTime() {
            if (reads.incrementAndGet() > 2 * CAP) {
                while (true) {
                    LockSupport.park(this);
                }
            }
            return now.get();
        }

        @Override
        public void sleep(Duration wait) throws InterruptedException {
            if (waits.size() >= CAP) {
                new CountDownLatch(1).await();
            }
            waits.add(wait.toSeconds());
            now.addAndGet(wait.toNanos());
        }
    }
}
