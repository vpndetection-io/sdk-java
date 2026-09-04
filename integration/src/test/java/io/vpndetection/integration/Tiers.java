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
     * a paid tier serves strictly more than the tier under it, while a free key and no key at all
     * are the same entitlement reached two ways.
     *
     * <p>Field COUNTS are deliberately absent. Pinning "starter answers seven fields" turns a
     * pricing change into a red SDK build; the relation between the tiers is what the client
     * actually has to keep.
     */
    record Rung(String tier, String secret, boolean widens) {}

    static final List<Rung> RUNGS = List.of(
            new Rung("unauth", null, false),
            new Rung("free", "VPNDETECTION_STAGING_KEY_FREE", false),
            new Rung("starter", "VPNDETECTION_STAGING_KEY_STARTER", true),
            new Rung("scale", "VPNDETECTION_STAGING_KEY_SCALE", true),
            new Rung("max", "VPNDETECTION_STAGING_KEY_MAX", true));

    static Rung unauth() {
        return RUNGS.get(0);
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
