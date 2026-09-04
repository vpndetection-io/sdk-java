package io.vpndetection.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vpndetection.Bogon;
import io.vpndetection.BatchResult;
import io.vpndetection.Result;
import io.vpndetection.integration.Staging.Answer;
import io.vpndetection.integration.Staging.Probe;
import io.vpndetection.integration.Tiers.Rung;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * The published library looking addresses up against the staging API.
 *
 * <p>Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each one serving a
 * superset of the tier below it, so a pricing change stays a pricing change instead of arriving as
 * a red SDK build.
 */
class LookupTest {
    @Test
    void anUnauthenticatedLookupAnswersIpAndIsVpn() {
        Answer answer = Staging.answerFor(Tiers.unauth());

        assertEquals(Staging.PROBE, answer.raw().get("ip"));
        assertInstanceOf(Boolean.class, answer.raw().get("is_vpn"));
        Staging.assertServedByTier(answer);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyedTiers")
    void aKeyReachesTheWireAndItsAnswerKeepsTheShape(Rung rung) {
        skipUnlessObservable(rung);

        Answer answer = Staging.answerFor(rung);

        // Staging.answerFor fails the run outright when a keyed tier answered unauthenticated;
        // saying it again here is what makes this test about the key rather than about the shape.
        assertTrue(answer.carriedKey(), rung.tier() + ": the key never reached the wire");
        Staging.assertServedByTier(answer);
    }

    @Test
    void eachTierServesASupersetOfTheTierBelow() {
        skipWithoutALadder();

        String belowTier = null;
        Set<String> below = null;
        for (Rung rung : Tiers.observable()) {
            Set<String> fields = Staging.answerFor(rung).raw().keySet();
            System.out.println(rung.tier() + ": " + fields.size() + " fields");
            if (below != null) {
                for (String field : below) {
                    assertTrue(fields.contains(field),
                            rung.tier() + " drops a field " + belowTier + " serves");
                }
                // Without this a run whose keys all resolved to one plan would pass: identical sets
                // satisfy containment in both directions.
                if (rung.widens()) {
                    assertTrue(fields.size() > below.size(),
                            rung.tier() + " answers no more fields than " + belowTier);
                }
            }
            belowTier = rung.tier();
            below = fields;
        }
    }

    @Test
    void aFieldAHigherTierServesIsAbsentOnALowerOneNeverFalse() {
        skipWithoutALadder();

        List<Rung> rungs = Tiers.observable();
        List<Answer> answers = rungs.stream().map(Staging::answerFor).toList();
        int compared = 0;

        for (int i = 0; i < answers.size(); i++) {
            Answer lower = answers.get(i);
            Set<String> above = new LinkedHashSet<>();
            answers.subList(i + 1, answers.size()).forEach(higher -> above.addAll(higher.raw().keySet()));
            for (String field : above) {
                if (lower.raw().containsKey(field) || !Staging.ACCESSORS.containsKey(field)) {
                    continue;
                }
                assertTrue(Staging.ACCESSORS.get(field).apply(lower.result()).isEmpty(),
                        field + " is not in the " + rungs.get(i).tier() + " plan, so it must read as empty");
                compared++;
            }
        }

        // Every tier answering the same fields makes this test a no-op, which is what a run whose
        // keys all resolved to one plan looks like. Say so rather than passing on nothing.
        Assumptions.assumeTrue(compared > 0, "no observable tier serves a field another one lacks");
    }

    @Test
    void aBogonIsAnsweredWithoutTouchingTheNetwork() {
        Probe probe = Staging.clientFor(Tiers.unauth());

        Result result = probe.client().lookup("10.0.0.1");

        assertEquals(List.of(), probe.recorder().facts(), "the bogon path reached the network");
        assertTrue(result.isBogon());
        assertFalse(result.isVpn());
        assertTrue(Bogon.isBogon("10.0.0.1"), "the standalone form must agree");
        // A bogon answers the WIDEST shape whatever the plan: every flag present and false, every
        // detail object present and empty. It is the one answer nobody should read a plan from.
        Staging.ACCESSORS.forEach((field, accessor) -> {
            Optional<?> held = accessor.apply(result);
            assertTrue(held.isPresent(), "a bogon answers every member, and " + field + " is missing");
            if (field.startsWith("is_")) {
                assertEquals(false, held.get(), "a bogon must answer " + field + " false, not empty");
            }
        });
    }

    @Test
    void aBatchCollapsesDuplicatesAndKeepsBogonsOffTheWire() {
        Probe probe = Staging.clientFor(Tiers.unauth());

        LinkedHashMap<String, BatchResult> got = probe.client().lookupBatch(
                List.of(Staging.PROBE, "8.8.8.8", Staging.PROBE, "10.0.0.1", "8.8.8.8"));

        assertEquals(List.of(Staging.PROBE, "8.8.8.8", "10.0.0.1"), List.copyOf(got.keySet()));
        // Distinct paths rather than a call count, so a retry against a wobbling staging cannot
        // read as a failure to deduplicate.
        Set<String> asked = new TreeSet<>();
        probe.recorder().facts().forEach(fact -> asked.add(fact.path()));
        assertEquals(new TreeSet<>(Set.of("/8.8.8.8", "/" + Staging.PROBE)), asked,
                "the batch asked for something other than the two servable addresses");
        assertTrue(got.get("10.0.0.1").orElseThrow().isBogon());
        for (String ip : List.of(Staging.PROBE, "8.8.8.8")) {
            assertTrue(got.get(ip).isSuccess(), ip + " failed: " + got.get(ip));
        }
    }

    static List<Rung> keyedTiers() {
        return Tiers.RUNGS.stream().filter(rung -> rung.secret() != null).toList();
    }

    private static void skipUnlessObservable(Rung rung) {
        Assumptions.assumeTrue(Tiers.skipFor(rung) == null, () -> Tiers.skipFor(rung));
    }

    // The ladder needs two rungs to say anything. The unauthenticated one is always there, so this
    // only fires when no tier secret at all is configured.
    private static void skipWithoutALadder() {
        Assumptions.assumeTrue(Tiers.observable().size() >= 2,
                "no tier secret is set, so there is no ladder to compare");
    }
}
