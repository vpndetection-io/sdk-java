package io.vpndetection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * A 2xx a call cannot read is a retried {@code SERVER_ERROR} carrying the status, never a raw
 * runtime error or a null handed back as the answer. 6.5.0 read an HTML, {@code []} or cut-off 200
 * as a {@code NETWORK} error with no status, raised a raw {@code NullPointerException} for an empty
 * or {@code null} one, and answered {@code {}} as a model of nulls (measured 2026-10-17).
 */
final class UnreadableAnswerTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** An answer each JSON call reads whole, which every case below takes one thing away from. */
    private static final Map<String, String> WHOLE = new LinkedHashMap<>();

    static {
        WHOLE.put("8.8.8.8", "{\"ip\": \"8.8.8.8\", \"is_vpn\": false, \"is_hosting\": true,"
                + " \"hosting\": {\"provider\": \"Google\", \"confidence\": \"high\", \"last_seen\": \"2026-10-17\"},"
                + " \"is_dcproxy\": true, \"dcproxy\": {\"provider\": \"p\", \"first_seen\": \"2026-06-14\","
                + " \"last_seen\": \"2026-10-17\", \"hits\": 3, \"hits_days_pct\": 4, \"providers_num\": 1}}");
        WHOLE.put("myip", "{\"ip\": \"203.0.114.7\", \"is_vpn\": true}");
        WHOLE.put("api/v1/entitlement", "{\"org_id\": \"6f1c2a52-6c83-4c8a-9a3e-2f3b8c1d0e9f\","
                + " \"apikey\": {\"id\": \"0b6e2d8a-1c4f-4a5e-8d7b-3e2f1a0c9b8d\", \"expires\": null,"
                + " \"allowed_cidrs\": []}, \"plan\": {\"key\": \"scale\", \"tier\": \"scale\"},"
                + " \"usage\": {\"requests\": 12, \"quota\": 100000, \"hard_limit\": null,"
                + " \"window_start\": \"2026-10-01T00:00:00Z\", \"window_end\": \"2026-11-01T00:00:00Z\"}}");
        WHOLE.put("api/v1/database/list", "{\"databases\": [{\"base\": \"vpn_ip\", \"name\": \"VPN IP\","
                + " \"summary\": \"rows\", \"license_type\": \"standard\", \"in_term\": true, \"open\": false,"
                + " \"starts\": null, \"expires\": null, \"renews_at\": null, \"notice_due_at\": null,"
                + " \"standing\": \"licensed\", \"versions\": [{\"id\": \"vpn_ip_extended_v1\", \"version\": 1,"
                + " \"formats\": [{\"format\": \"mmdb\", \"bytes\": 1234}]}]}]}");
        WHOLE.put("api/v1/database/metadata", "{\"id\": \"vpn_ip_extended_v1\", \"updated\": \"2026-10-01\","
                + " \"entries\": 42, \"schema\": {\"mmdb\": [{\"name\": \"ip\", \"type\": \"string\"}]},"
                + " \"size\": {\"mmdb\": 1234}}");
        WHOLE.put("api/v1/database/checksum", "{\"id\": \"vpn_ip_extended_v1\", \"format\": \"mmdb\","
                + " \"checksums\": {\"md5\": \"m\", \"sha1\": \"s1\", \"sha256\": \"s256\", \"sha512\": \"s512\"}}");
        WHOLE.put("api/v1/database/downloads", "{\"downloads\": [{\"dataset_id\": \"vpn_ip_extended_v1\","
                + " \"format\": \"mmdb\", \"outcome\": \"ok\", \"sample\": false, \"open\": false, \"bytes\": 1234,"
                + " \"http_status\": 302, \"apikey_id\": null, \"client_ip\": null, \"user_agent\": null,"
                + " \"created\": \"2026-10-01T10:00:00Z\"}]}");
    }

    private static final List<String> UNREADABLE = List.of(
            "<html>gateway</html>", "{\"ip\": \"8.8.8.8\", \"is_vp", "", "null", "[]", "{}");

    @Test
    void theWholeAnswersRead() {
        Map<String, StubHttpClient.Route> routes = new HashMap<>();
        WHOLE.forEach((path, body) -> routes.put(path, StubHttpClient.Route.ok(body)));
        try (VPNDetection client = clientOn(StubHttpClient.of(routes)).build()) {
            for (String path : WHOLE.keySet()) {
                call(client, path);
            }
        }
    }

    @Test
    void a200TheCallCannotReadIsARetriedServerErrorWithItsStatus() {
        for (String path : WHOLE.keySet()) {
            for (String body : UNREADABLE) {
                assertRetriedServerError(path, body, path + " '" + body + "'");
            }
        }
        for (String body : List.of("{\"databases\": null}", "{\"databases\": [{}]}", "{\"databases\": [null]}")) {
            assertRetriedServerError("api/v1/database/list", body, body);
        }
        for (String body : List.of("{\"downloads\": null}", "{\"downloads\": [{}]}", "{\"downloads\": [null]}")) {
            assertRetriedServerError("api/v1/database/downloads", body, body);
        }
        assertRetriedServerError("api/v1/database/checksum", "{\"checksums\": null}", "checksums null");
        assertRetriedServerError("api/v1/database/checksum", "{\"checksums\": {}}", "checksums {}");
    }

    /**
     * One member per case, left out and then sent as null, from an otherwise whole answer: a body
     * missing several at once lets a decoder that defaults all but one of them pass.
     */
    @Test
    void anAnswerWithoutAMemberTheSpecRequiresIsARetriedServerError() throws IOException {
        List<List<String>> cases = List.of(
                List.of("8.8.8.8", "", "ip", "is_vpn"),
                List.of("myip", "", "ip", "is_vpn"),
                List.of("api/v1/entitlement", "", "org_id", "apikey", "plan", "usage"),
                List.of("api/v1/entitlement", "/apikey", "id", "allowed_cidrs"),
                List.of("api/v1/entitlement", "/plan", "key", "tier"),
                List.of("api/v1/entitlement", "/usage", "requests", "quota", "window_start", "window_end"),
                List.of("api/v1/database/list", "/databases/0", "base", "name", "summary", "in_term", "standing",
                        "open", "versions"),
                List.of("api/v1/database/list", "/databases/0/versions/0", "id", "version", "formats"),
                List.of("api/v1/database/list", "/databases/0/versions/0/formats/0", "format"),
                List.of("api/v1/database/metadata", "", "id", "updated", "entries", "schema"),
                List.of("api/v1/database/metadata", "/schema/mmdb/0", "name", "type"),
                List.of("api/v1/database/checksum", "", "id", "format", "checksums"),
                List.of("api/v1/database/checksum", "/checksums", "md5", "sha1", "sha256", "sha512"),
                List.of("api/v1/database/downloads", "/downloads/0", "dataset_id", "format", "outcome", "sample",
                        "open", "created"));
        for (List<String> each : cases) {
            String path = each.get(0);
            for (String member : each.subList(2, each.size())) {
                for (boolean drop : new boolean[] {true, false}) {
                    JsonNode body = MAPPER.readTree(WHOLE.get(path));
                    ObjectNode holder = (ObjectNode) body.at(each.get(1));
                    if (drop) {
                        assertTrue(holder.remove(member) != null, member + " is not at " + each.get(1));
                    } else {
                        holder.putNull(member);
                    }
                    assertRetriedServerError(path, MAPPER.writeValueAsString(body),
                            path + " " + each.get(1) + " " + member + (drop ? " left out" : " null"));
                }
            }
        }
    }

    /**
     * A member of the wrong type, nested or a numeric string where a number is due, is no answer
     * either: Jackson's own coercions read {@code "3"} as 3 and {@code 3} as "3".
     */
    @Test
    void aMemberOfTheWrongTypeIsARetriedServerError() throws IOException {
        List<List<String>> cases = List.of(
                List.of("8.8.8.8", "", "is_vpn", "\"false\""),
                List.of("8.8.8.8", "", "is_hosting", "\"yes\""),
                List.of("8.8.8.8", "", "is_hosting", "1"),
                List.of("8.8.8.8", "", "ip", "8"),
                List.of("8.8.8.8", "/hosting", "provider", "3"),
                List.of("8.8.8.8", "/dcproxy", "hits", "\"3\""),
                List.of("8.8.8.8", "/dcproxy", "hits_days_pct", "4.5"),
                List.of("myip", "", "is_vpn", "\"true\""),
                List.of("api/v1/entitlement", "/usage", "requests", "\"12\""),
                List.of("api/v1/database/list", "/databases/0/versions/0", "version", "\"3\""),
                List.of("api/v1/database/list", "/databases/0/versions/0", "version", "\"x\""),
                List.of("api/v1/database/list", "/databases/0", "in_term", "\"yes\""),
                List.of("api/v1/database/list", "/databases/0/versions/0/formats/0", "bytes", "\"1234\""),
                List.of("api/v1/database/metadata", "", "entries", "\"42\""),
                List.of("api/v1/database/metadata", "/size", "mmdb", "\"760\""),
                List.of("api/v1/database/downloads", "/downloads/0", "bytes", "\"1234\""),
                List.of("api/v1/database/downloads", "/downloads/0", "sample", "\"no\""));
        for (List<String> each : cases) {
            JsonNode body = MAPPER.readTree(WHOLE.get(each.get(0)));
            ((ObjectNode) body.at(each.get(1))).set(each.get(2), MAPPER.readTree(each.get(3)));
            assertRetriedServerError(each.get(0), MAPPER.writeValueAsString(body),
                    each.get(0) + " " + each.get(1) + " " + each.get(2) + " = " + each.get(3));
        }
    }

    /**
     * A null inside a list or map, a value outside an enum and a sample row that is no object, each
     * in an otherwise whole answer. Through 6.9.1 each came back as an answer, a {@code license_type}
     * outside its enum as null, which reads as no license at all.
     */
    @Test
    void aNullEntryAValueOutsideItsEnumOrARowThatIsNoObjectIsARetriedServerError() throws IOException {
        List<List<Object>> cases = List.of(
                List.of("8.8.8.8", "", "pubproxy", Map.of("protocols", Arrays.asList((Object) null))),
                List.of("api/v1/database/list", "/databases/0/versions/0", "sample_formats", Arrays.asList((Object) null)),
                List.of("api/v1/database/list", "/databases/0", "license_type", "perpetual"),
                List.of("api/v1/database/list", "/databases/0", "license_type", 1),
                List.of("api/v1/database/metadata", "", "sample", Map.of("mmdb", Arrays.asList((Object) null))),
                List.of("api/v1/database/metadata", "", "sample", Map.of("mmdb", List.of(List.of("10.0.0.0/8")))),
                List.of("api/v1/database/metadata", "", "sample", Map.of("mmdb", List.of("10.0.0.0/8"))),
                List.of("api/v1/database/metadata", "", "sample", Map.of("mmdb", List.of(5))),
                List.of("api/v1/database/metadata", "", "sample", Collections.singletonMap("mmdb", null)),
                List.of("api/v1/database/metadata", "", "sample_size", Collections.singletonMap("mmdb", null)));
        for (List<Object> each : cases) {
            String path = (String) each.get(0);
            JsonNode body = MAPPER.readTree(WHOLE.get(path));
            JsonNode value = MAPPER.valueToTree(each.get(3));
            ((ObjectNode) body.at((String) each.get(1))).set((String) each.get(2), value);
            assertRetriedServerError(path, MAPPER.writeValueAsString(body),
                    path + " " + each.get(1) + " " + each.get(2) + " = " + value);
        }

        JsonNode metadata = MAPPER.readTree(WHOLE.get("api/v1/database/metadata"));
        ((ObjectNode) metadata).set("sample", MAPPER.readTree("{\"mmdb\": [{\"ip\": \"10.0.0.0/8\", \"note\": null}]}"));
        try (VPNDetection client = clientOn(StubHttpClient.of(Map.of("api/v1/database/metadata",
                StubHttpClient.Route.ok(MAPPER.writeValueAsString(metadata))))).build()) {
            assertEquals(1, client.database().metadata("vpn_ip_extended_v1").getSample().get("mmdb").size(),
                    "a null inside a row is the row's own");
        }
    }

    /**
     * The spec's {@code date} and {@code date-time} are RFC 3339's, and only those are read. Through
     * 6.9.1 Jackson's readers took a Unix time as a number or a numeric string, a date sent as a
     * date-time, an epoch day or an array, a padded value, an offset without its colon or minutes or
     * with seconds, no seconds, a year past four digits, and {@code ""} as no date at all.
     */
    @Test
    void aDateIsReadAsRfc3339AndNothingElse() throws IOException {
        List<Object> dateTimes = List.of("2026-10-05T10:00:00", " 2026-10-05T10:00:00Z", "2026-10-05T10:00:00Z ",
                "2026-10-05T10:00:00+0500", "2026-10-05T10:00:00+05", "2026-10-05T10:00:00+05:00:30",
                "2026-10-05T10:00Z", "2026-10-05 10:00:00Z", "2026-10-05T10:00:00+24:00", "2026-10-05T10:00:00+05:60",
                "+12026-10-05T10:00:00Z", "2026-10-05T10:00:00.Z", "2026-10-05T10:00:00,5Z", "2026-10-05T10:00:60Z",
                "2026-10-05T24:00:00Z", "2026-02-30T10:00:00Z", "2026-10-5T10:00:00Z", "2026-W41-1T10:00:00Z",
                "20261005T100000Z", "2026-10-05", "1700000000", "1.5", 1700000000, 1.5, "x", "tomorrow", "");
        List<Object> dates = List.of(" 2026-10-05", "2026-10-05 ", "2026-10-05T10:00:00", "2026-10-05T10:00:00Z",
                "+12026-10-05", "-2026-10-05", "2026-10-05Z", "20261005", "2026-W41-1", "2026-278", "2026-02-30",
                "2026-10-5", 20000, List.of(2026, 10, 5), "x", "monday", "");
        List<List<Object>> cases = new ArrayList<>();
        for (Object value : dateTimes) {
            cases.add(List.of("api/v1/database/list", "/databases/0", "starts", value));
            cases.add(List.of("api/v1/database/downloads", "/downloads/0", "created", value));
            cases.add(List.of("api/v1/entitlement", "/usage", "window_start", value));
            cases.add(List.of("api/v1/entitlement", "/apikey", "expires", value));
        }
        for (Object value : dates) {
            cases.add(List.of("api/v1/database/metadata", "", "updated", value));
            cases.add(List.of("8.8.8.8", "/hosting", "last_seen", value));
            cases.add(List.of("8.8.8.8", "/dcproxy", "first_seen", value));
        }
        for (List<Object> each : cases) {
            String path = (String) each.get(0);
            JsonNode body = MAPPER.readTree(WHOLE.get(path));
            JsonNode value = MAPPER.valueToTree(each.get(3));
            ((ObjectNode) body.at((String) each.get(1))).set((String) each.get(2), value);
            assertRetriedServerError(path, MAPPER.writeValueAsString(body), path + " " + each.get(2) + " = " + value);
        }

        Map<String, OffsetDateTime> readable = Map.of(
                "2026-10-05T10:00:00Z", OffsetDateTime.of(2026, 10, 5, 10, 0, 0, 0, ZoneOffset.UTC),
                "2026-10-05t10:00:00.5z", OffsetDateTime.of(2026, 10, 5, 10, 0, 0, 500_000_000, ZoneOffset.UTC),
                "2026-10-05T10:00:00-00:00", OffsetDateTime.of(2026, 10, 5, 10, 0, 0, 0, ZoneOffset.UTC),
                "2026-10-05T10:00:00.1234567891-05:30",
                OffsetDateTime.of(2026, 10, 5, 10, 0, 0, 123_456_789, ZoneOffset.ofHoursMinutes(-5, -30)),
                "2026-10-05T23:59:59+18:00", OffsetDateTime.of(2026, 10, 5, 23, 59, 59, 0, ZoneOffset.ofHours(18)));
        for (var each : readable.entrySet()) {
            JsonNode list = MAPPER.readTree(WHOLE.get("api/v1/database/list"));
            ((ObjectNode) list.at("/databases/0")).put("starts", each.getKey());
            JsonNode entitlement = MAPPER.readTree(WHOLE.get("api/v1/entitlement"));
            ((ObjectNode) entitlement.at("/usage")).put("window_start", each.getKey());
            try (VPNDetection client = clientOn(StubHttpClient.of(Map.of(
                    "api/v1/database/list", StubHttpClient.Route.ok(MAPPER.writeValueAsString(list)),
                    "api/v1/entitlement", StubHttpClient.Route.ok(MAPPER.writeValueAsString(entitlement))))).build()) {
                assertEquals(each.getValue(), client.database().list().get(0).getStarts(), each.getKey());
                assertEquals(each.getValue(), client.myEntitlement().getUsage().getWindowStart(), each.getKey());
            }
        }
        try (VPNDetection client = clientOn(StubHttpClient.of(Map.of(
                "api/v1/database/metadata", StubHttpClient.Route.ok(WHOLE.get("api/v1/database/metadata")),
                "8.8.8.8", StubHttpClient.Route.ok(WHOLE.get("8.8.8.8"))))).build()) {
            assertEquals(LocalDate.of(2026, 10, 1), client.database().metadata("vpn_ip_extended_v1").getUpdated());
            assertEquals(LocalDate.of(2026, 6, 14), client.lookup("8.8.8.8").raw().getDcproxy().getFirstSeen());
        }
    }

    /**
     * A chunk the batch cannot read fails every address in it, retried; an entry it cannot read is
     * that address's failure alone, and the rest of the chunk is answered.
     */
    @Test
    void aBatchReadsItsChunkWholeAndEachEntryOnItsOwn() {
        List<String> ips = List.of("8.8.8.8", "1.1.1.1");
        for (String body : List.of("<html>gateway</html>", "{\"results\": {", "", "null", "[]", "{}",
                "{\"results\": [], \"errors\": null}")) {
            StubHttpClient http = StubHttpClient.of(Map.of()).answeringBatchWith(StubHttpClient.Route.ok(body));
            try (VPNDetection client = clientOn(http).retries(1).build()) {
                Map<String, BatchResult> out = client.lookupBatch(ips);
                for (String ip : ips) {
                    VPNDetectionException err = out.get(ip).error().orElseThrow(() -> new AssertionError(body));
                    assertEquals(ErrorKind.SERVER_ERROR, err.kind(), "'" + body + "' " + ip);
                    assertEquals(200, err.statusCode().orElseThrow(), "'" + body + "' " + ip);
                }
                assertEquals(2, http.calls.size(), "'" + body + "': retried");
            }
        }
        String whole = "{\"ip\": \"1.1.1.1\", \"is_vpn\": false}";
        for (String entry : List.of("{}", "null", "[]", "\"x\"", "{\"ip\": \"8.8.8.8\"}",
                "{\"ip\": \"8.8.8.8\", \"is_vpn\": \"yes\"}",
                "{\"ip\": \"8.8.8.8\", \"is_vpn\": true, \"vpn\": {\"provider\": 3}}")) {
            String body = "{\"results\": {\"8.8.8.8\": " + entry + ", \"1.1.1.1\": " + whole + "}, \"errors\": {}}";
            StubHttpClient http = StubHttpClient.of(Map.of()).answeringBatchWith(StubHttpClient.Route.ok(body));
            try (VPNDetection client = clientOn(http).retries(1).build()) {
                Map<String, BatchResult> out = client.lookupBatch(ips);
                VPNDetectionException err = out.get("8.8.8.8").error().orElseThrow(() -> new AssertionError(entry));
                assertEquals(ErrorKind.SERVER_ERROR, err.kind(), entry);
                assertEquals(200, err.statusCode().orElseThrow(), entry);
                assertEquals("1.1.1.1", out.get("1.1.1.1").orElseThrow().ip(), entry);
                assertEquals(1, http.calls.size(), entry + ": an entry is never retried");
            }
        }
        String body = "{\"results\": {\"1.1.1.1\": " + whole + "}, \"errors\": {\"8.8.8.8\": {\"status\": \"x\"}}}";
        StubHttpClient http = StubHttpClient.of(Map.of()).answeringBatchWith(StubHttpClient.Route.ok(body));
        try (VPNDetection client = clientOn(http).retries(1).build()) {
            VPNDetectionException err = client.lookupBatch(ips).get("8.8.8.8").error().orElseThrow();
            assertEquals(ErrorKind.SERVER_ERROR, err.kind(), "an unreadable error entry");
            assertEquals(200, err.statusCode().orElseThrow());
        }
    }

    /** A download link answered 200 rather than 302 carries its status. */
    @Test
    void aDownloadLinkAnswered200CarriesItsStatus() {
        StubHttpClient http = StubHttpClient.of(Map.of("api/v1/database/download", StubHttpClient.Route.ok("{}")));
        try (VPNDetection client = clientOn(http).retries(1).build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class,
                    () -> client.database().downloadUrl("vpn_ip_extended_v1", DatabaseFormat.MMDB));
            assertEquals(ErrorKind.SERVER_ERROR, err.kind());
            assertEquals(200, err.statusCode().orElseThrow());
            assertEquals(2, http.calls.size(), "retried");
        }
    }

    /**
     * The table is the spec's {@code required} lists less what each marks nullable, which the
     * generator writes as the models' {@code @Nonnull} fields, so a re-pin that adds one turns this
     * red until the table has it. Every model an answer reaches must be in the table.
     */
    @Test
    void theRequiredMembersAreTheModelsNonnullOnes() throws ReflectiveOperationException {
        Set<Class<?>> envelopes = Set.of(io.vpndetection.model.DatabaseList.class,
                io.vpndetection.model.DownloadList.class, io.vpndetection.model.DatabaseChecksumsResponse.class);
        Set<Class<?>> unchecked = Set.of(io.vpndetection.model.VpnDetail.class, io.vpndetection.model.ClassDetail.class,
                io.vpndetection.model.ProxyDetail.class, io.vpndetection.model.PubproxyDetail.class);
        Set<Class<?>> reached = new LinkedHashSet<>();
        List<Class<?>> pending = new ArrayList<>(envelopes);
        pending.add(io.vpndetection.model.DatabaseMetadata.class);
        pending.add(io.vpndetection.model.LookupResponse.class);
        pending.add(io.vpndetection.model.Entitlement.class);
        while (!pending.isEmpty()) {
            Class<?> model = pending.remove(pending.size() - 1);
            if (!reached.add(model)) {
                continue;
            }
            Set<String> nonnull = new TreeSet<>();
            for (java.lang.reflect.Field constant : model.getFields()) {
                if (!constant.getName().startsWith("JSON_PROPERTY_")) {
                    continue;
                }
                String member = (String) constant.get(null);
                java.lang.reflect.Field field = model.getDeclaredField(camel(member));
                if (field.isAnnotationPresent(javax.annotation.Nonnull.class)) {
                    nonnull.add(member);
                }
                models(field.getGenericType(), pending);
            }
            if (unchecked.contains(model)) {
                assertEquals(Set.of(), nonnull, model.getSimpleName() + " has required members now");
                continue;
            }
            List<String> table = RequiredMembers.MEMBERS.get(model);
            assertTrue(table != null, model.getSimpleName() + " is not in the table");
            assertEquals(nonnull, new TreeSet<>(table), model.getSimpleName());
        }
        reached.removeAll(unchecked);
        assertEquals(RequiredMembers.MEMBERS.keySet(), reached);
    }

    private static void assertRetriedServerError(String path, String body, String label) {
        StubHttpClient http = StubHttpClient.of(Map.of(path, StubHttpClient.Route.ok(body)));
        try (VPNDetection client = clientOn(http).retries(1).build()) {
            VPNDetectionException err = assertThrows(VPNDetectionException.class, () -> call(client, path), label);
            assertEquals(ErrorKind.SERVER_ERROR, err.kind(), label);
            assertEquals(200, err.statusCode().orElseThrow(), label);
            assertEquals(2, http.calls.size(), label + ": retried");
        }
    }

    private static String camel(String member) {
        StringBuilder out = new StringBuilder();
        boolean upper = false;
        for (char c : member.toCharArray()) {
            if (c == '_') {
                upper = true;
            } else {
                out.append(upper ? Character.toUpperCase(c) : c);
                upper = false;
            }
        }
        return out.toString();
    }

    private static void models(java.lang.reflect.Type type, List<Class<?>> into) {
        if (type instanceof java.lang.reflect.ParameterizedType parameterized) {
            for (java.lang.reflect.Type argument : parameterized.getActualTypeArguments()) {
                models(argument, into);
            }
        } else if (type instanceof Class<?> model && !model.isEnum()
                && model.getPackageName().equals("io.vpndetection.model")) {
            into.add(model);
        }
    }

    private static void call(VPNDetection client, String path) {
        switch (path) {
            case "8.8.8.8" -> client.lookup("8.8.8.8");
            case "myip" -> client.myIp();
            case "api/v1/entitlement" -> client.myEntitlement();
            case "api/v1/database/list" -> client.database().list();
            case "api/v1/database/metadata" -> client.database().metadata("vpn_ip_extended_v1");
            case "api/v1/database/checksum" -> client.database().checksums("vpn_ip_extended_v1", DatabaseFormat.MMDB);
            default -> client.database().downloads();
        }
    }

    private static VPNDetection.Builder clientOn(StubHttpClient http) {
        return VPNDetection.builder().httpClient(http).apiKey("k").cacheEnabled(false);
    }
}
