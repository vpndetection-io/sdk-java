package io.vpndetection.integration;

import java.util.List;
import java.util.Objects;

/**
 * Which plan tiers this run can observe, and the secret each one needs.
 *
 * <p>A tier is observable only when its secret holds something non-empty. Actions interpolates a
 * secret that does not exist to an EMPTY STRING rather than leaving the variable unset, and a
 * client built with an empty key sends no credential at all, so an empty key would run as a second
 * unauthenticated client and every comparison against it would be vacuously true.
 */
final class Tiers {
    private Tiers() {}

    /**
     * One rung per plan tier, ascending.
     *
     * <p>{@code widens} is what the rung promises against whichever observable rung sits below it:
     * the first paid tier serves strictly more than no key; every paid plan answers the same
     * fields, so a higher paid tier only keeps what the one under it serves. The trial rung's key
     * is on the free plan: its answer is a paid one for its organization's daily trial, the first
     * 100 lookups of the UTC day, and Unlimited's after, so it promises nothing and is never the
     * rung a later one is compared against.
     *
     * <p>Field COUNTS are deliberately absent. Pinning "starter answers seven fields" turns a
     * pricing change into a red SDK build; the relation between the tiers is what the client
     * actually has to keep.
     */
    record Rung(String tier, String secret, boolean widens) {}

    static final List<Rung> RUNGS = List.of(
            new Rung("unauth", null, false),
            new Rung("trial", "VPNDETECTION_STAGING_KEY_FREE", false),
            new Rung("starter", "VPNDETECTION_STAGING_KEY_STARTER", true),
            new Rung("scale", "VPNDETECTION_STAGING_KEY_SCALE", false),
            new Rung("max", "VPNDETECTION_STAGING_KEY_MAX", false));

    static Rung unauth() {
        return RUNGS.get(0);
    }

    /** A key on the free plan, with its daily trial. */
    static Rung trial() {
        return RUNGS.get(1);
    }

    /** The cheapest rung a batch can run on: POST /batch needs a paid plan. */
    static Rung paid() {
        return RUNGS.get(2);
    }

    static Rung max() {
        return RUNGS.get(RUNGS.size() - 1);
    }

    /** The key for a rung, or the empty string when it has none or its secret is unset. */
    static String keyFor(Rung rung) {
        if (rung.secret() == null) {
            return "";
        }
        return Objects.requireNonNullElse(System.getenv(rung.secret()), "").trim();
    }

    /** A reason to skip, or null when the rung can run. */
    static String skipFor(Rung rung) {
        if (rung.secret() == null || !keyFor(rung).isEmpty()) {
            return null;
        }
        return rung.secret() + " is not set, so the " + rung.tier() + " tier cannot be exercised";
    }

    static List<Rung> observable() {
        return RUNGS.stream().filter(rung -> skipFor(rung) == null).toList();
    }
}
