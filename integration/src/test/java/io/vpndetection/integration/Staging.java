package io.vpndetection.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.Result;
import io.vpndetection.VPNDetection;
import io.vpndetection.integration.Tiers.Rung;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * The staging fixtures the test files share: one client per tier, one lookup per tier, and the
 * shape rules that hold whatever the plan.
 */
final class Staging {
    private Staging() {}

    static final String STAGING = "https://api-staging.vpndetection.io";
    static final String STAGING_HOST = "api-staging.vpndetection.io";

    /** A stable VPN address, and the one the README teaches. */
    static final String PROBE = "45.83.91.1";

    /**
     * What a POPULATED detail object carries. {@code required} holds on every tier that serves the
     * object at all; {@code optional} is the max-only remainder, which is absent rather than empty
     * on a lower plan.
     */
    record Detail(List<String> required, List<String> optional) {}

    private static final List<String> CLASS_KEYS = List.of("provider", "confidence", "last_seen");
    private static final List<String> PROXY_KEYS =
            List.of("provider", "first_seen", "last_seen", "hits", "hits_days_pct", "providers_num");

    /** One entry per dataset the API answers about. */
    static final Map<String, Detail> MEMBERS = members();

    /**
     * The wire name of every tier-gated field, mapped to the accessor the client puts it on. That
     * pairing is what lets one assertion talk about the wire and the binding at once.
     *
     * <p>{@code ip} and {@code is_vpn} are absent on purpose: they are on every plan, so they are
     * never the subject of an absent-versus-false question.
     */
    static final Map<String, Function<Result, Optional<?>>> ACCESSORS = accessors();

    /** One tier's client, and the recorder underneath it. */
    record Probe(VPNDetection client, RecordingHttpClient recorder) {}

    /** One tier's answer, alongside what the wire actually carried. */
    record Answer(Rung rung, Result result, Map<String, Object> raw, boolean carriedKey) {}

    private static final Map<String, Answer> ANSWERS = new ConcurrentHashMap<>();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static Probe clientFor(Rung rung) {
        String key = Tiers.keyFor(rung);
        RecordingHttpClient recorder = new RecordingHttpClient(
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), key);
        VPNDetection.Builder builder = VPNDetection.builder().baseUrl(STAGING).httpClient(recorder);
        if (!key.isEmpty()) {
            builder.apiKey(key);
        }
        return new Probe(builder.build(), recorder);
    }

    /**
     * One lookup per tier for the whole run. The client caches, so a second reader of the same tier
     * would cost no request either, but the fixture also carries what the wire said, which the
     * client does not keep.
     */
    static Answer answerFor(Rung rung) {
        return ANSWERS.computeIfAbsent(rung.tier(), tier -> {
            Probe probe = clientFor(rung);
            Result result = probe.client().lookup(PROBE);
            boolean carried = probe.recorder().carriedKey();
            // Checked HERE rather than in one test, so no comparison anywhere can be made against a
            // tier that silently ran unauthenticated: an unsent key answers the free shape, which
            // satisfies every containment check vacuously.
            if (rung.secret() != null && !carried) {
                fail(tier + ": the key never reached the wire");
            }
            return new Answer(rung, result, jsonBody(probe.recorder(), "/" + PROBE), carried);
        });
    }

    static void assertServedByTier(Answer answer) {
        assertEquals(PROBE, answer.result().ip());
        assertFalse(answer.result().isBogon(), "a served answer is not a local one");
        assertShape(answer);
    }

    /**
     * Holds on every plan: presence is the plan, the value is the answer.
     *
     * <p>Read off the wire, then cross-checked against the typed accessor. That pairing is both
     * halves of the absent-versus-false contract at once: a field the plan includes must survive
     * the mapping, {@code false} and all, and one it does not must read as empty rather than as a
     * plausible {@code false}.
     */
    static void assertShape(Answer answer) {
        Map<String, Object> raw = answer.raw();
        Result result = answer.result();
        String tier = answer.rung().tier();

        assertInstanceOf(String.class, raw.get("ip"), tier + ": ip is on every plan");
        assertInstanceOf(Boolean.class, raw.get("is_vpn"), tier + ": is_vpn is on every plan");
        assertEquals(raw.get("is_vpn"), result.isVpn(), tier + ": is_vpn was decoded into something else");

        ACCESSORS.forEach((field, accessor) -> {
            Optional<?> held = accessor.apply(result);
            if (!raw.containsKey(field)) {
                assertTrue(held.isEmpty(),
                        tier + ": " + field + " is not in this plan, so it must read as empty");
                return;
            }
            assertFalse(held.isEmpty(), tier + ": " + field + " is served and the client dropped it");
        });

        MEMBERS.forEach((name, spec) -> {
            if (!raw.containsKey(name)) {
                return;
            }
            // A detail object without its flag would leave a caller reading the object to find out
            // whether the address is flagged at all.
            assertTrue(raw.containsKey("is_" + name), tier + ": " + name + " is served without its flag");
            assertDetail(tier, name, spec, raw);
        });
    }

    @SuppressWarnings("unchecked")
    private static void assertDetail(String tier, String name, Detail spec, Map<String, Object> raw) {
        Object object = raw.get(name);
        assertInstanceOf(Map.class, object, tier + ": " + name + " must be an object when present");
        Map<String, Object> fields = (Map<String, Object>) object;
        if (fields.isEmpty()) {
            assertEquals(Boolean.FALSE, raw.get("is_" + name),
                    tier + ": " + name + " is empty, so its flag must be false");
            return;
        }
        for (String key : spec.required()) {
            assertTrue(fields.containsKey(key), tier + ": " + name + " is populated but carries no " + key);
        }
        for (String key : fields.keySet()) {
            assertTrue(spec.required().contains(key) || spec.optional().contains(key),
                    tier + ": " + name + "." + key + " is not a documented key of this detail object");
        }
    }

    /** The captured answer to one path, as a map of exactly what the wire carried. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> jsonBody(RecordingHttpClient recorder, String path) {
        byte[] raw = recorder.body(path)
                .orElseThrow(() -> new AssertionError("no JSON answer was captured for " + path));
        try {
            return MAPPER.readValue(raw, Map.class);
        } catch (IOException e) {
            throw new AssertionError("parsing the answer to " + path, e);
        }
    }

    private static Map<String, Detail> members() {
        Map<String, Detail> map = new LinkedHashMap<>();
        map.put("vpn", new Detail(List.of("provider", "last_seen"), List.of("confidence", "method")));
        map.put("hosting", new Detail(CLASS_KEYS, List.of()));
        map.put("relay", new Detail(CLASS_KEYS, List.of()));
        map.put("tor", new Detail(CLASS_KEYS, List.of()));
        map.put("cdn", new Detail(CLASS_KEYS, List.of()));
        map.put("resproxy", new Detail(PROXY_KEYS, List.of()));
        map.put("dcproxy", new Detail(PROXY_KEYS, List.of()));
        map.put("mobproxy", new Detail(PROXY_KEYS, List.of()));
        return Collections.unmodifiableMap(map);
    }

    private static Map<String, Function<Result, Optional<?>>> accessors() {
        Map<String, Function<Result, Optional<?>>> map = new LinkedHashMap<>();
        map.put("vpn", Result::vpn);
        map.put("is_hosting", Result::isHosting);
        map.put("hosting", Result::hosting);
        map.put("is_relay", Result::isRelay);
        map.put("relay", Result::relay);
        map.put("is_tor", Result::isTor);
        map.put("tor", Result::tor);
        map.put("is_cdn", Result::isCdn);
        map.put("cdn", Result::cdn);
        map.put("is_resproxy", Result::isResproxy);
        map.put("resproxy", Result::resproxy);
        map.put("is_dcproxy", Result::isDcproxy);
        map.put("dcproxy", Result::dcproxy);
        map.put("is_mobproxy", Result::isMobproxy);
        map.put("mobproxy", Result::mobproxy);
        return Collections.unmodifiableMap(map);
    }
}
