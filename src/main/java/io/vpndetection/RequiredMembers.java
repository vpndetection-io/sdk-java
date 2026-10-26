package io.vpndetection;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.std.DelegatingDeserializer;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.LogicalType;

import io.vpndetection.model.Asn;
import io.vpndetection.model.BatchLookupError;
import io.vpndetection.model.BatchLookupResponse;
import io.vpndetection.model.Database;
import io.vpndetection.model.DatabaseChecksumsResponse;
import io.vpndetection.model.DatabaseFormatSize;
import io.vpndetection.model.DatabaseList;
import io.vpndetection.model.DatabaseMetadata;
import io.vpndetection.model.DatabaseMetadataColumn;
import io.vpndetection.model.DatabaseVersion;
import io.vpndetection.model.DbChecksums;
import io.vpndetection.model.Download;
import io.vpndetection.model.DownloadList;
import io.vpndetection.model.Entitlement;
import io.vpndetection.model.EntitlementApikey;
import io.vpndetection.model.EntitlementPlan;
import io.vpndetection.model.EntitlementUsage;
import io.vpndetection.model.Location;
import io.vpndetection.model.LookupResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Refuses an answer without a member it must carry, or with a member of the wrong type, or holding
 * one the spec does not allow.
 *
 * <p>The generator starts every list member at an empty list and every other member at null, so
 * {@code {}} decoded as a lookup of nulls, an empty catalog or no downloads, and an entry without
 * its members as a model of nulls (6.5.0, measured 2026-10-17); once decoded, the absence could not
 * be seen. Each member is checked on the tree before the generated model is built, so a body without
 * one, or with one null or holding a null, fails to decode, which {@link Wire} makes a retried
 * {@link ErrorKind#SERVER_ERROR} carrying the status. Jackson's own coercions are turned off for the
 * same reason: it read {@code "3"} as the number 3 and {@code 3} as the string "3".
 *
 * <p>Through 6.9.1 an optional list or map holding a null (a lookup's {@code pubproxy.protocols}
 * included), a sample row that is no object, a checksum answer without its {@code id} or
 * {@code format}, and a {@code license_type} outside its enum, which the generated nullable enum
 * reads as null, all came back as answers (measured 2026-10-26).
 *
 * <p>A batch is the exception, since an entry it cannot read is that address's failure alone: such
 * an entry is dropped from the chunk before it is built, and the client reports the address as one
 * the answer did not include.
 */
final class RequiredMembers extends BeanDeserializerModifier {
    /**
     * By the generated model that carries them: each schema's {@code required} list less the members
     * it marks nullable, which a test holds to the models' own {@code @Nonnull} fields. An envelope
     * needs only the member its call returns.
     */
    static final Map<Class<?>, List<String>> MEMBERS = Map.ofEntries(
            Map.entry(LookupResponse.class, List.of("ip", "is_vpn")),
            Map.entry(Location.class, List.of("continent", "continent_name", "country", "country_name", "timezone",
                    "currency_code", "currency_name", "currency_symbol", "flag_emoji", "flag_unicode")),
            Map.entry(Asn.class, List.of("asn", "name", "domain", "type", "prefix")),
            Map.entry(Entitlement.class, List.of("org_id", "apikey", "plan", "usage")),
            Map.entry(EntitlementApikey.class, List.of("id", "allowed_cidrs")),
            Map.entry(EntitlementPlan.class, List.of("key", "tier")),
            Map.entry(EntitlementUsage.class, List.of("requests", "quota", "window_start", "window_end")),
            Map.entry(DatabaseList.class, List.of("databases")),
            Map.entry(DownloadList.class, List.of("downloads")),
            Map.entry(DatabaseChecksumsResponse.class, List.of("id", "format", "checksums")),
            Map.entry(Database.class, List.of("base", "name", "summary", "in_term", "standing", "open", "versions")),
            Map.entry(DatabaseVersion.class, List.of("id", "version", "formats")),
            Map.entry(DatabaseFormatSize.class, List.of("format")),
            Map.entry(DatabaseMetadata.class, List.of("id", "updated", "entries", "schema")),
            Map.entry(DatabaseMetadataColumn.class, List.of("name", "type")),
            Map.entry(DbChecksums.class, List.of("md5", "sha1", "sha256", "sha512")),
            Map.entry(Download.class, List.of("dataset_id", "format", "outcome", "sample", "open", "created")));

    /** The members whose entries the spec types as objects, by model, which no generated type checks. */
    static final Map<Class<?>, String> OBJECT_ROWS = Map.of(DatabaseMetadata.class, "sample");

    /**
     * The generated client's mapper, made to refuse what the generated models cannot tell apart: no
     * scalar read from another JSON type, dates read as RFC 3339 alone, and this module.
     */
    static ObjectMapper configure(ObjectMapper mapper) {
        for (LogicalType type : List.of(LogicalType.Integer, LogicalType.Float, LogicalType.Boolean)) {
            mapper.coercionConfigFor(type).setCoercion(CoercionInputShape.String, CoercionAction.Fail);
        }
        mapper.coercionConfigFor(LogicalType.Integer).setCoercion(CoercionInputShape.Float, CoercionAction.Fail);
        mapper.coercionConfigFor(LogicalType.Boolean).setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
        for (CoercionInputShape shape : List.of(CoercionInputShape.Integer, CoercionInputShape.Float,
                CoercionInputShape.Boolean)) {
            mapper.coercionConfigFor(LogicalType.Textual).setCoercion(shape, CoercionAction.Fail);
        }
        SimpleModule module = new SimpleModule("vpndetection-required-members");
        module.setDeserializerModifier(new RequiredMembers());
        return mapper.registerModule(Rfc3339.module()).registerModule(module);
    }

    @Override
    public JsonDeserializer<?> modifyDeserializer(DeserializationConfig config, BeanDescription description,
            JsonDeserializer<?> deserializer) {
        if (description.getBeanClass() == BatchLookupResponse.class) {
            return new Batch(deserializer);
        }
        Class<?> model = description.getBeanClass();
        if (!model.getPackageName().equals(Database.class.getPackageName())) {
            return deserializer;
        }
        // A map's values are checked like a list's entries, and an enum's value against its
        // constants; a model's members are its own deserializer's to check.
        Set<String> lists = new HashSet<>();
        Set<String> maps = new HashSet<>();
        Map<String, Set<String>> enums = new HashMap<>();
        for (BeanPropertyDefinition property : description.findProperties()) {
            Class<?> type = property.getRawPrimaryType();
            if (Map.class.isAssignableFrom(type)) {
                maps.add(property.getName());
            } else if (Collection.class.isAssignableFrom(type)) {
                lists.add(property.getName());
            } else if (type.isEnum()) {
                enums.put(property.getName(), Arrays.stream(type.getEnumConstants())
                        .map(String::valueOf).collect(Collectors.toUnmodifiableSet()));
            }
        }
        return new Requiring(deserializer, MEMBERS.getOrDefault(model, List.of()), Set.copyOf(lists),
                Set.copyOf(maps), Map.copyOf(enums), OBJECT_ROWS.get(model));
    }

    private static final class Requiring extends DelegatingDeserializer {
        private final List<String> members;
        private final Set<String> lists;
        private final Set<String> maps;
        private final Map<String, Set<String>> enums;
        private final String objectRows;

        Requiring(JsonDeserializer<?> delegate, List<String> members, Set<String> lists, Set<String> maps,
                Map<String, Set<String>> enums, String objectRows) {
            super(delegate);
            this.members = members;
            this.lists = lists;
            this.maps = maps;
            this.enums = enums;
            this.objectRows = objectRows;
        }

        @Override
        protected JsonDeserializer<?> newDelegatingInstance(JsonDeserializer<?> delegate) {
            return new Requiring(delegate, members, lists, maps, enums, objectRows);
        }

        @Override
        public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            JsonNode tree = context.readTree(parser);
            if (!tree.isObject()) {
                return context.reportInputMismatch(this, "the answer is not an object");
            }
            for (String member : members) {
                JsonNode value = tree.get(member);
                if (value == null || value.isNull()) {
                    return context.reportInputMismatch(this, "the answer has no %s", member);
                }
            }
            for (Map.Entry<String, JsonNode> member : tree.properties()) {
                String name = member.getKey();
                JsonNode value = member.getValue();
                if ((lists.contains(name) || maps.contains(name)) && holdsNull(value, maps.contains(name))) {
                    return context.reportInputMismatch(this, "the answer's %s holds a null", name);
                }
                Set<String> constants = enums.get(name);
                if (constants != null && !value.isNull() && !(value.isTextual() && constants.contains(value.asText()))) {
                    return context.reportInputMismatch(this, "the answer's %s is not one of %s", name, constants);
                }
                if (name.equals(objectRows) && !rowsAreObjects(value)) {
                    return context.reportInputMismatch(this, "the answer's %s holds a row that is not an object", name);
                }
            }
            try (JsonParser read = tree.traverse(parser.getCodec())) {
                read.nextToken();
                return _delegatee.deserialize(read, context);
            }
        }

        private static boolean holdsNull(JsonNode value, boolean map) {
            if (!value.isArray() && !(map && value.isObject())) {
                return false;
            }
            for (JsonNode entry : value) {
                if (entry.isNull() || holdsNull(entry, false)) {
                    return true;
                }
            }
            return false;
        }

        // A map of lists, as the sample's rows keyed by format; any other shape is the generated
        // type's to refuse.
        private static boolean rowsAreObjects(JsonNode value) {
            for (JsonNode rows : value) {
                for (JsonNode row : rows) {
                    if (!row.isObject()) {
                        return false;
                    }
                }
            }
            return true;
        }
    }

    /**
     * A batch chunk: an object holding {@code results} or {@code errors}, or the chunk fails whole.
     * Each entry is read on its own, and one that does not read is left out.
     */
    private static final class Batch extends DelegatingDeserializer {
        Batch(JsonDeserializer<?> delegate) {
            super(delegate);
        }

        @Override
        protected JsonDeserializer<?> newDelegatingInstance(JsonDeserializer<?> delegate) {
            return new Batch(delegate);
        }

        @Override
        public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException {
            JsonNode tree = context.readTree(parser);
            if (!tree.isObject() || !(tree.path("results").isObject() || tree.path("errors").isObject())) {
                return context.reportInputMismatch(this, "the batch answer holds neither results nor errors");
            }
            ObjectNode chunk = (ObjectNode) tree;
            ObjectMapper mapper = (ObjectMapper) parser.getCodec();
            drop(chunk, "results", mapper, LookupResponse.class);
            drop(chunk, "errors", mapper, BatchLookupError.class);
            try (JsonParser read = chunk.traverse(parser.getCodec())) {
                read.nextToken();
                return _delegatee.deserialize(read, context);
            }
        }

        private static void drop(ObjectNode chunk, String member, ObjectMapper mapper, Class<?> type) {
            JsonNode entries = chunk.get(member);
            if (entries == null || !entries.isObject()) {
                chunk.remove(member);
                return;
            }
            List<String> unreadable = new ArrayList<>();
            entries.fields().forEachRemaining(entry -> {
                if (!readable(entry.getValue(), mapper, type)) {
                    unreadable.add(entry.getKey());
                }
            });
            ((ObjectNode) entries).remove(unreadable);
        }

        private static boolean readable(JsonNode entry, ObjectMapper mapper, Class<?> type) {
            if (!entry.isObject()) {
                return false;
            }
            if (type != LookupResponse.class
                    && !(entry.path("status").isInt() && entry.path("error").isTextual())) {
                return false;
            }
            try {
                mapper.treeToValue(entry, type);
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }
}
