package io.vpndetection;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * The bogon predicate, standing on its own for code that has no client to hand.
 *
 * <p>{@link VPNDetection#isBogon(String)} is the same check reached from a client you already hold,
 * which is how the README teaches it. Java forbids a static and an instance method of the same
 * signature in one class, so the standalone form lives here.
 */
public final class Bogon {
    private Bogon() {}

    /**
     * Whether an address is a bogon: private, loopback, link-local, documentation, multicast or
     * otherwise not routable on the public internet, including the IPv6 equivalents and the 6to4
     * and Teredo ranges that wrap them.
     *
     * <p>These can never be VPN or proxy infrastructure, so the client answers them itself and they
     * never cost a request. Anything that does not parse as an address is not a bogon.
     */
    public static boolean isBogon(String ip) {
        if (ip == null) {
            return false;
        }
        if (ip.indexOf(':') >= 0) {
            BigInteger a = parseV6(ip);
            return a != null && contains(V6, a);
        }
        BigInteger a = parseV4(ip);
        return a != null && contains(V4, a);
    }

    private static boolean contains(List<Range> ranges, BigInteger addr) {
        for (Range r : ranges) {
            if (addr.and(r.mask).equals(r.network)) {
                return true;
            }
        }
        return false;
    }

    // The canonical CIDRs, parsed once when this class is first used rather than on every call.
    private static final List<Range> V4 = parseRanges(Bogons.V4, 32, false);
    private static final List<Range> V6 = parseRanges(Bogons.V6, 128, true);

    private static final class Range {
        final BigInteger network;
        final BigInteger mask;

        Range(BigInteger network, BigInteger mask) {
            this.network = network;
            this.mask = mask;
        }
    }

    private static List<Range> parseRanges(List<String> cidrs, int width, boolean v6) {
        List<Range> out = new ArrayList<>(cidrs.size());
        for (String cidr : cidrs) {
            int slash = cidr.indexOf('/');
            int bits = Integer.parseInt(cidr.substring(slash + 1));
            BigInteger mask = BigInteger.ONE.shiftLeft(width)
                    .subtract(BigInteger.ONE)
                    .shiftLeft(width - bits)
                    .and(BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE));
            String net = cidr.substring(0, slash);
            BigInteger addr = v6 ? parseV6(net) : parseV4(net);
            out.add(new Range(addr.and(mask), mask));
        }
        return List.copyOf(out);
    }

    private static BigInteger parseV4(String ip) {
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        BigInteger n = BigInteger.ZERO;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return null;
            }
            int octet = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return null;
                }
                octet = octet * 10 + (c - '0');
            }
            if (octet > 255) {
                return null;
            }
            n = n.shiftLeft(8).or(BigInteger.valueOf(octet));
        }
        return n;
    }

    // Handles the `::` run and a trailing IPv4 literal (::ffff:1.2.3.4), which several of the
    // canonical ranges use.
    private static BigInteger parseV6(String ip) {
        String a = ip;
        int lastColon = a.lastIndexOf(':');
        if (lastColon >= 0 && a.indexOf('.', lastColon) >= 0) {
            BigInteger tail = parseV4(a.substring(lastColon + 1));
            if (tail == null) {
                return null;
            }
            a = a.substring(0, lastColon + 1)
                    + String.format("%04x:%04x", tail.shiftRight(16).intValue(), tail.intValue() & 0xffff);
        }

        int run = a.indexOf("::");
        List<String> field;
        if (run < 0) {
            field = splitFields(a);
            if (field.size() != 8) {
                return null;
            }
        } else {
            if (a.indexOf("::", run + 1) >= 0) {
                return null;
            }
            List<String> head = splitFields(a.substring(0, run));
            List<String> tail = splitFields(a.substring(run + 2));
            int fill = 8 - head.size() - tail.size();
            if (fill < 0) {
                return null;
            }
            field = new ArrayList<>(8);
            field.addAll(head);
            for (int i = 0; i < fill; i++) {
                field.add("0");
            }
            field.addAll(tail);
        }

        BigInteger n = BigInteger.ZERO;
        for (String group : field) {
            if (group.isEmpty() || group.length() > 4) {
                return null;
            }
            int value = 0;
            for (int i = 0; i < group.length(); i++) {
                int digit = Character.digit(group.charAt(i), 16);
                if (digit < 0) {
                    return null;
                }
                value = (value << 4) | digit;
            }
            n = n.shiftLeft(16).or(BigInteger.valueOf(value));
        }
        return n;
    }

    private static List<String> splitFields(String s) {
        List<String> out = new ArrayList<>(8);
        for (String part : s.split(":", -1)) {
            if (!part.isEmpty()) {
                out.add(part);
            }
        }
        return out;
    }
}
