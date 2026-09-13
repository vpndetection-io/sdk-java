package io.vpndetection.middleware;

/**
 * A bound on a numeric member. Every side set must hold, so two of them are a range:
 * {@code Bound.gte(5).lt(100)}.
 */
public final class Bound {
    private final Double gte;
    private final Double gt;
    private final Double lte;
    private final Double lt;

    private Bound(Double gte, Double gt, Double lte, Double lt) {
        this.gte = gte;
        this.gt = gt;
        this.lte = lte;
        this.lt = lt;
    }

    /** At or above {@code value}. */
    public static Bound gte(double value) {
        return new Bound(value, null, null, null);
    }

    /** Strictly above {@code value}. */
    public static Bound gt(double value) {
        return new Bound(null, value, null, null);
    }

    /** At or below {@code value}. */
    public static Bound lte(double value) {
        return new Bound(null, null, value, null);
    }

    /** Strictly below {@code value}. */
    public static Bound lt(double value) {
        return new Bound(null, null, null, value);
    }

    /** Narrows this bound, so {@code gte(5).lt(100)} is a range. */
    public Bound andGte(double value) {
        return new Bound(value, gt, lte, lt);
    }

    /** Narrows this bound. */
    public Bound andGt(double value) {
        return new Bound(gte, value, lte, lt);
    }

    /** Narrows this bound. */
    public Bound andLte(double value) {
        return new Bound(gte, gt, value, lt);
    }

    /** Narrows this bound. */
    public Bound andLt(double value) {
        return new Bound(gte, gt, lte, value);
    }

    boolean matches(Object got) {
        if (!(got instanceof Number number)) {
            return false;
        }
        double value = number.doubleValue();
        if (gte != null && value < gte) {
            return false;
        }
        if (gt != null && value <= gt) {
            return false;
        }
        if (lte != null && value > lte) {
            return false;
        }
        return lt == null || value < lt;
    }

    @Override
    public String toString() {
        return "Bound[gte=" + gte + ", gt=" + gt + ", lte=" + lte + ", lt=" + lt + "]";
    }
}
