package io.vpndetection.middleware;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.github.benmanes.caffeine.cache.Ticker;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * What an address's crawler agents are remembered for: an hour from its first one, which adding
 * another does not extend. The cache's clock is moved rather than waited on.
 */
class CrawlerAgentsTest {
    private static final String IP = "66.249.66.1";

    private static String crawler(int n) {
        return "Mozilla/5.0 (compatible; Examplebot/" + n + ".0)";
    }

    private static void pass(AtomicLong now, Duration time) {
        now.addAndGet(time.toNanos());
    }

    @Test
    void anAddressIsRememberedAnHourFromItsFirstAgentAndAnotherAgentDoesNotExtendIt() {
        AtomicLong now = new AtomicLong();
        Ticker ticker = now::get;
        CrawlerAgents agents = new CrawlerAgents(ticker);
        for (int n = 1; n <= 3; n++) {
            assertEquals(crawler(n), agents.claim(IP, crawler(n)).agent());
        }
        pass(now, Duration.ofMinutes(50));
        assertEquals(crawler(4), agents.claim(IP, crawler(4)).agent(), "the fourth, ten minutes before the hour");
        assertNull(agents.claim(IP, crawler(5)).agent(), "a fifth is refused while the four are remembered");

        pass(now, Duration.ofMinutes(10).minusMillis(1));
        assertNull(agents.claim(IP, crawler(5)).agent(), "still remembered a millisecond before the hour");

        pass(now, Duration.ofMillis(1));
        assertEquals(crawler(5), agents.claim(IP, crawler(5)).agent(), "forgotten an hour after the first");
        assertEquals(crawler(1), agents.claim(IP, crawler(1)).agent());
    }

    @Test
    void readingAnAgentAgainDoesNotExtendItEither() {
        AtomicLong now = new AtomicLong();
        Ticker ticker = now::get;
        CrawlerAgents agents = new CrawlerAgents(ticker);
        for (int n = 1; n <= 4; n++) {
            agents.claim(IP, crawler(n));
        }
        pass(now, Duration.ofMinutes(59));
        assertEquals(crawler(1), agents.claim(IP, crawler(1)).agent());
        pass(now, Duration.ofMinutes(1));
        assertEquals(crawler(5), agents.claim(IP, crawler(5)).agent());
    }

    @Test
    void aHeaderNamingNoCrawlerHasNoClaim() {
        CrawlerAgents agents = new CrawlerAgents();
        assertNull(agents.claim(IP, null));
        assertNull(agents.claim(IP, ""));
        assertNull(agents.claim(IP, "curl/8.0"));
        assertNotNull(agents.claim(IP, "Googlebot/2.1"));
    }
}
