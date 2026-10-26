package io.vpndetection;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the spec's {@code date} and {@code date-time} as RFC 3339 spells them, and nothing else.
 *
 * <p>Jackson's own readers took far more (6.9.1, measured 2026-10-26): a number or a numeric string
 * as a Unix time ({@code 1700000000}, {@code "1.5"}), a {@code date} sent as a date-time, an epoch
 * day or {@code [2026,10,5]}, a padded value, {@code +0500}, {@code +05} and {@code +05:00:30}, no
 * seconds, a year past four digits, and {@code ""} as null. RFC 3339's lowercase {@code t} and
 * {@code z} are read, as they were.
 */
final class Rfc3339 {
    private Rfc3339() {}

    private static final Pattern DATE = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})");
    private static final Pattern DATE_TIME = Pattern.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]"
            + "([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]+))?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))");

    static SimpleModule module() {
        SimpleModule module = new SimpleModule("vpndetection-rfc3339");
        module.addDeserializer(LocalDate.class, new JsonDeserializer<>() {
            @Override
            public LocalDate deserialize(JsonParser parser, DeserializationContext context) throws IOException {
                String value = text(parser, context, LocalDate.class);
                LocalDate date = date(value);
                return date != null ? date
                        : (LocalDate) context.handleWeirdStringValue(LocalDate.class, value, "not an RFC 3339 date");
            }
        });
        module.addDeserializer(OffsetDateTime.class, new JsonDeserializer<>() {
            @Override
            public OffsetDateTime deserialize(JsonParser parser, DeserializationContext context) throws IOException {
                String value = text(parser, context, OffsetDateTime.class);
                OffsetDateTime time = dateTime(value);
                return time != null ? time
                        : (OffsetDateTime) context.handleWeirdStringValue(OffsetDateTime.class, value,
                                "not an RFC 3339 date-time");
            }
        });
        return module;
    }

    // A date is a string, so a number, an array or an object is the wrong type, as it is for any
    // other string member.
    private static String text(JsonParser parser, DeserializationContext context, Class<?> type) throws IOException {
        if (parser.currentToken() != JsonToken.VALUE_STRING) {
            context.handleUnexpectedToken(type, parser);
        }
        return parser.getText();
    }

    /** The day {@code value} names, or null when it is not RFC 3339's full-date or names no real day. */
    static LocalDate date(String value) {
        Matcher m = DATE.matcher(value);
        if (!m.matches()) {
            return null;
        }
        try {
            return LocalDate.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)));
        } catch (DateTimeException noSuchDay) {
            return null;
        }
    }

    /**
     * The time {@code value} names, at the offset it was given in, or null when it is not RFC
     * 3339's date-time or names no real time. A leap second and an offset past 18 hours are refused,
     * as {@code java.time} can hold neither, and a fraction past nanoseconds is cut.
     */
    static OffsetDateTime dateTime(String value) {
        Matcher m = DATE_TIME.matcher(value);
        if (!m.matches()) {
            return null;
        }
        try {
            String fraction = m.group(7) == null ? "" : m.group(7);
            int nanos = fraction.isEmpty() ? 0
                    : Integer.parseInt((fraction + "00000000").substring(0, 9));
            LocalDateTime local = LocalDateTime.of(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)),
                    Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)), Integer.parseInt(m.group(5)),
                    Integer.parseInt(m.group(6)), nanos);
            ZoneOffset offset = ZoneOffset.UTC;
            if (m.group(8) != null) {
                int sign = m.group(8).equals("-") ? -1 : 1;
                offset = ZoneOffset.ofHoursMinutes(sign * Integer.parseInt(m.group(9)),
                        sign * Integer.parseInt(m.group(10)));
            }
            return OffsetDateTime.of(local, offset);
        } catch (DateTimeException noSuchTime) {
            return null;
        }
    }
}
