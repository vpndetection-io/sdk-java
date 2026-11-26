package io.vpndetection.middleware;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Ticker;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * The crawler agents each address was looked up with. Only a crawler's agent is sent, and an
 * address claiming more than {@link Core#MAX_AGENTS_PER_ADDRESS} of them in an hour sends none past
 * those, so a visitor inventing an agent per request spends at most that many lookups.
 */
final class CrawlerAgents {
    /** How long an address's agents are remembered, from its first one: the client's default TTL. */
    static final Duration REMEMBERED = Duration.ofHours(1);

    // One weight budget for both bounds: an address weighs ENTRY_WEIGHT plus its agents' characters,
    // so the cache holds at most 10,000 addresses, and fewer once their agents are long.
    private static final int ENTRY_WEIGHT = 400;
    private static final long MAX_WEIGHT = 10_000L * ENTRY_WEIGHT;

    /** What a request's agent comes to: the agent the lookup sends, null past the address's bound. */
    record Claim(String agent) {}

    private final Cache<String, List<String>> seen;

    CrawlerAgents() {
        this(Ticker.systemTicker());
    }

    CrawlerAgents(Ticker ticker) {
        this.seen = Caffeine.newBuilder()
                .maximumWeight(MAX_WEIGHT)
                .weigher((String ip, List<String> known) -> weight(known))
                .expireAfter(fromFirst())
                .ticker(ticker)
                .build();
    }

    /** This request's claim, or null when its header names no crawler: that one sends no agent. */
    Claim claim(String ip, String header) {
        if (header == null || header.isEmpty() || !Core.namesCrawler(header)) {
            return null;
        }
        Claim[] claim = new Claim[1];
        seen.asMap().compute(ip, (key, known) -> {
            if (known == null) {
                claim[0] = new Claim(header);
                return List.of(header);
            }
            if (known.contains(header)) {
                claim[0] = new Claim(header);
                return known;
            }
            if (known.size() >= Core.MAX_AGENTS_PER_ADDRESS) {
                claim[0] = new Claim(null);
                return known;
            }
            List<String> grown = new ArrayList<>(known);
            grown.add(header);
            claim[0] = new Claim(header);
            return List.copyOf(grown);
        });
        return claim[0];
    }

    private static int weight(List<String> known) {
        long chars = ENTRY_WEIGHT;
        for (String agent : known) {
            chars += agent.length();
        }
        return (int) Math.min(chars, Integer.MAX_VALUE);
    }

    // The hour runs from the address's first agent: adding one, or reading, leaves what is left.
    private static Expiry<String, List<String>> fromFirst() {
        return new Expiry<>() {
            @Override
            public long expireAfterCreate(String ip, List<String> known, long now) {
                return REMEMBERED.toNanos();
            }

            @Override
            public long expireAfterUpdate(String ip, List<String> known, long now, long left) {
                return left;
            }

            @Override
            public long expireAfterRead(String ip, List<String> known, long now, long left) {
                return left;
            }
        };
    }
}
