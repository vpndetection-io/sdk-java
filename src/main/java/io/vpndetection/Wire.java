package io.vpndetection;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.vpndetection.internal.ApiException;
import io.vpndetection.internal.ApiResponse;

import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.Year;
import java.time.ZoneOffset;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The seam between the generated wire layer and this one: retries, and the generated
 * {@link ApiException} turned into a {@link VPNDetectionException}.
 */
final class Wire {
    private Wire() {}

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration BACKOFF_BASE = Duration.ofMillis(200);
    private static final Duration BACKOFF_CAP = Duration.ofSeconds(8);
    // The longest Retry-After waited as given, 2^31 - 1 ms (~24.8 days). Past it the backoff runs
    // instead: as given, 2147484 held a call 24.8 days, and 9223372036854776 or more failed it with a
    // raw ArithmeticException out of Duration.toMillis (measured 2026-10-04 on 6.3.3).
    private static final Duration LONGEST_WAIT = Duration.ofMillis(Integer.MAX_VALUE);

    private static final Pattern SECONDS = Pattern.compile("[0-9]+");
    private static final List<String> MONTHS =
            List.of("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    private static final String MONTH = "(" + String.join("|", MONTHS) + ")";
    private static final String TIME = "([0-9]{2}):([0-9]{2}):([0-9]{2})";
    private static final String DAY = "(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)";
    // Sun, 06 Nov 1994 08:49:37 GMT
    private static final Pattern IMF_FIXDATE =
            Pattern.compile(DAY + ", ([0-9]{2}) " + MONTH + " ([0-9]{4}) " + TIME + " GMT");
    // Sunday, 06-Nov-94 08:49:37 GMT
    private static final Pattern RFC_850 = Pattern.compile(
            "(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), ([0-9]{2})-" + MONTH
                    + "-([0-9]{2}) " + TIME + " GMT");
    // Sun Nov  6 08:49:37 1994
    private static final Pattern ASCTIME =
            Pattern.compile(DAY + " " + MONTH + " ([ 0-9][0-9]) " + TIME + " ([0-9]{4})");

    interface Call<T> {
        T invoke() throws ApiException;
    }

    /** One attempt that reports its own failure, for a request the generated layer does not make. */
    interface Attempt<T> {
        T invoke();
    }

    /** Runs a generated call, retrying a transient failure up to {@code retries} times. */
    static <T> T execute(int retries, Call<T> call) {
        return retrying(retries, () -> {
            try {
                return call.invoke();
            } catch (ApiException e) {
                throw translate(e);
            }
        });
    }

    /**
     * Retries a transient failure up to {@code retries} times.
     *
     * <p>A server-supplied {@code Retry-After} wins over the backoff schedule, and is also the only
     * thing that makes a 429 retryable at all. One past {@link #LONGEST_WAIT} is waited out on the
     * backoff instead, and the failure still carries the server's value.
     */
    static <T> T retrying(int retries, Attempt<T> attempt) {
        for (int i = 0; ; i++) {
            VPNDetectionException failure;
            try {
                return attempt.invoke();
            } catch (VPNDetectionException e) {
                failure = e;
            }
            if (i >= retries || !failure.retryable()) {
                throw failure;
            }
            Duration asked = failure.retryAfter().orElse(null);
            sleep(asked != null && asked.compareTo(LONGEST_WAIT) <= 0 ? asked : backoff(i));
        }
    }

    /**
     * The answer of a 2xx. An empty body or {@code null} is no answer at all: a retried
     * {@code SERVER_ERROR} carrying the status, never a null handed back as if it were the answer.
     */
    static <T> T answer(ApiResponse<T> response, String name) {
        return member(response, Function.identity(), name);
    }

    /**
     * The member of a 2xx answer a call returns. An answer without it - {@code {}}, {@code null}, an
     * empty body - is no answer at all, and fails as {@link #answer} does.
     */
    static <T, M> M member(ApiResponse<T> response, Function<T, M> member, String name) {
        T data = response.getData();
        M value = data == null ? null : member.apply(data);
        if (value == null) {
            throw new VPNDetectionException(ErrorKind.SERVER_ERROR, "the API answered with no " + name,
                    response.getStatusCode(), null, null);
        }
        return value;
    }

    static VPNDetectionException translate(ApiException e) {
        int status = e.getCode();
        // The generated layer decodes only once a 2xx has arrived, and drops its status when the body
        // is not the JSON it expects: a proxy's page, a cut-off body, an answer without a member it
        // must carry. Every call it decodes answers 200.
        if (status == 0 && e.getCause() instanceof JsonProcessingException) {
            return new VPNDetectionException(ErrorKind.SERVER_ERROR,
                    "the API did not answer with the JSON this call reads", 200, null, e.getCause());
        }
        if (status == 0) {
            return new VPNDetectionException(ErrorKind.NETWORK, messageOf(e), null, null, e.getCause());
        }
        Duration retryAfter = retryAfterOf(e);
        return new VPNDetectionException(kindOf(status, retryAfter), messageOf(e), status, retryAfter, null);
    }

    /**
     * A per-entry failure inside a successful batch: the status the single lookup would have
     * answered, and its message, with no headers at all - so a 429 here is a spent allowance, which
     * is the only kind the API puts in an entry.
     */
    static VPNDetectionException fromEntry(int status, String message) {
        return new VPNDetectionException(kindOf(status, null), message, status, null, null);
    }

    /**
     * What an HTTP status means, for the generated calls and for the raw dataset transfer alike.
     *
     * @param retryAfter the response's {@code Retry-After}, which is the only thing separating a
     *     rate limit from a spent allowance.
     */
    static ErrorKind kindOf(int status, Duration retryAfter) {
        switch (status) {
            case 400:
                return ErrorKind.BAD_REQUEST;
            case 401:
                return ErrorKind.UNAUTHORIZED;
            case 403:
                return ErrorKind.FORBIDDEN;
            case 429:
                return retryAfter == null ? ErrorKind.QUOTA_EXCEEDED : ErrorKind.RATE_LIMITED;
            default:
                // Any other 4xx is a CLIENT error. Falling through to SERVER_ERROR would make it
                // retryable, so a bad dataset id would be retried twice before failing. Only 5xx
                // and transport failures are worth a retry.
                return status < 500 ? ErrorKind.BAD_REQUEST : ErrorKind.SERVER_ERROR;
        }
    }

    // The two APIs behind this host answer with different envelopes: the lookup endpoint uses
    // `error`, the database endpoints use `rc`. Both are read here so a caller never has to know
    // which one they hit.
    private static String messageOf(ApiException e) {
        String body = e.getResponseBody();
        if (body != null && !body.isBlank()) {
            try {
                JsonNode root = MAPPER.readTree(body);
                for (String field : new String[] {"error", "rc"}) {
                    JsonNode value = root.get(field);
                    if (value != null && value.isTextual()) {
                        return value.asText();
                    }
                }
            } catch (Exception ignored) {
                // A non-JSON body is not worth failing over; fall through to the generic message.
            }
        }
        if (e.getCode() != 0) {
            return "request failed with status " + e.getCode();
        }
        Throwable cause = e.getCause();
        return cause != null && cause.getMessage() != null ? cause.getMessage() : "request failed";
    }

    // A count of seconds past what a long holds, or a value in no form at all, is no Retry-After:
    // on a 429 that reads as a spent allowance.
    private static Duration retryAfterOf(ApiException e) {
        if (e.getResponseHeaders() == null) {
            return null;
        }
        String value = e.getResponseHeaders().firstValue("Retry-After").orElse(null);
        if (value == null || value.isBlank()) {
            return null;
        }
        value = value.trim();
        if (SECONDS.matcher(value).matches()) {
            try {
                return Duration.ofSeconds(Long.parseLong(value));
            } catch (NumberFormatException pastALong) {
                return null;
            }
        }
        Instant when = httpDate(value);
        if (when == null) {
            return null;
        }
        Duration wait = Duration.between(Instant.now(), when);
        return wait.isNegative() ? Duration.ZERO : wait;
    }

    // The instant an HTTP date names, or null when it is in none of the three forms or names no
    // real time, such as 31 November. The day of the week is read but not checked against the date.
    private static Instant httpDate(String value) {
        try {
            Matcher m = IMF_FIXDATE.matcher(value);
            if (m.matches()) {
                return at(Integer.parseInt(m.group(3)), m.group(2), m.group(1), m, 4);
            }
            m = RFC_850.matcher(value);
            if (m.matches()) {
                return at(fullYear(Integer.parseInt(m.group(3))), m.group(2), m.group(1), m, 4);
            }
            m = ASCTIME.matcher(value);
            if (m.matches()) {
                return at(Integer.parseInt(m.group(6)), m.group(1), m.group(2), m, 3);
            }
        } catch (DateTimeException noSuchTime) {
            return null;
        }
        return null;
    }

    // The hour, minute and second are the matcher's groups from `time` on.
    private static Instant at(int year, String month, String day, Matcher m, int time) {
        return LocalDateTime.of(year, MONTHS.indexOf(month) + 1, Integer.parseInt(day.trim()),
                Integer.parseInt(m.group(time)), Integer.parseInt(m.group(time + 1)),
                Integer.parseInt(m.group(time + 2))).toInstant(ZoneOffset.UTC);
    }

    // RFC 850's two-digit year, read as RFC 9110 says: one that would land more than 50 years ahead
    // is the most recent past year ending in those digits.
    private static int fullYear(int twoDigits) {
        int now = Year.now(ZoneOffset.UTC).getValue();
        int year = now - Math.floorMod(now, 100) + twoDigits;
        return year > now + 50 ? year - 100 : year;
    }

    private static Duration backoff(int attempt) {
        Duration wait = BACKOFF_BASE.multipliedBy(1L << Math.min(attempt, 16));
        return wait.compareTo(BACKOFF_CAP) > 0 ? BACKOFF_CAP : wait;
    }

    private static void sleep(Duration wait) {
        if (wait.isZero() || wait.isNegative()) {
            return;
        }
        try {
            Thread.sleep(wait.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VPNDetectionException(ErrorKind.NETWORK, "interrupted while waiting to retry", e);
        }
    }
}
