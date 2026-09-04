package io.vpndetection;

import io.vpndetection.model.ClassDetail;
import io.vpndetection.model.LookupResponse;
import io.vpndetection.model.ProxyDetail;
import io.vpndetection.model.VpnDetail;

import java.util.Objects;
import java.util.Optional;

/**
 * What a lookup answers.
 *
 * <p>An <b>empty</b> {@code Optional} is a member your plan does not include. It never means "we
 * could not check", so empty and {@code false} are genuinely different answers: empty is "not in
 * your plan", {@code false} is "checked, and no". Call {@code orElse(false)} on the Optional
 * for the common case where you only care whether the address is flagged.
 *
 * <p>A detail object that is present but empty means the flag above it is false. A populated one
 * always carries every one of its keys.
 */
public final class Result {
    private final LookupResponse raw;
    private final boolean bogon;

    private Result(LookupResponse raw, boolean bogon) {
        this.raw = raw;
        this.bogon = bogon;
    }

    static Result of(LookupResponse body) {
        return new Result(body, false);
    }

    /**
     * The answer a bogon gets, in the full shape the API serves at its widest plan: every flag
     * present and false, every detail object present and empty.
     *
     * <p>Note this is deliberately the WIDEST shape regardless of your plan, so do not infer which
     * fields your plan includes from a bogon answer. {@link #isBogon()} is how you tell a locally
     * computed answer from a served one.
     */
    static Result bogon(String ip) {
        LookupResponse r = new LookupResponse()
                .ip(ip)
                .isVpn(false)
                .isHosting(false)
                .isRelay(false)
                .isTor(false)
                .isCdn(false)
                .isResproxy(false)
                .isDcproxy(false)
                .isMobproxy(false)
                .vpn(new VpnDetail())
                .hosting(new ClassDetail())
                .relay(new ClassDetail())
                .tor(new ClassDetail())
                .cdn(new ClassDetail())
                .resproxy(new ProxyDetail())
                .dcproxy(new ProxyDetail())
                .mobproxy(new ProxyDetail());
        return new Result(r, true);
    }

    /** The address that was looked up, normalized. */
    public String ip() {
        return raw.getIp();
    }

    /** Whether the address is VPN infrastructure. Every plan includes this. */
    public boolean isVpn() {
        return Boolean.TRUE.equals(raw.getIsVpn());
    }

    /** Set when this answer was computed locally rather than served. */
    public boolean isBogon() {
        return bogon;
    }

    public Optional<Boolean> isHosting() {
        return Optional.ofNullable(raw.getIsHosting());
    }

    public Optional<Boolean> isRelay() {
        return Optional.ofNullable(raw.getIsRelay());
    }

    public Optional<Boolean> isTor() {
        return Optional.ofNullable(raw.getIsTor());
    }

    public Optional<Boolean> isCdn() {
        return Optional.ofNullable(raw.getIsCdn());
    }

    public Optional<Boolean> isResproxy() {
        return Optional.ofNullable(raw.getIsResproxy());
    }

    public Optional<Boolean> isDcproxy() {
        return Optional.ofNullable(raw.getIsDcproxy());
    }

    public Optional<Boolean> isMobproxy() {
        return Optional.ofNullable(raw.getIsMobproxy());
    }

    public Optional<VpnDetail> vpn() {
        return Optional.ofNullable(raw.getVpn());
    }

    public Optional<ClassDetail> hosting() {
        return Optional.ofNullable(raw.getHosting());
    }

    public Optional<ClassDetail> relay() {
        return Optional.ofNullable(raw.getRelay());
    }

    public Optional<ClassDetail> tor() {
        return Optional.ofNullable(raw.getTor());
    }

    public Optional<ClassDetail> cdn() {
        return Optional.ofNullable(raw.getCdn());
    }

    public Optional<ProxyDetail> resproxy() {
        return Optional.ofNullable(raw.getResproxy());
    }

    public Optional<ProxyDetail> dcproxy() {
        return Optional.ofNullable(raw.getDcproxy());
    }

    public Optional<ProxyDetail> mobproxy() {
        return Optional.ofNullable(raw.getMobproxy());
    }

    /**
     * The response exactly as it came off the wire, with its original names.
     *
     * <p>For a bogon this is synthesized locally rather than served; {@link #isBogon()} is how you
     * tell the two apart.
     */
    public LookupResponse raw() {
        return raw;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Result)) {
            return false;
        }
        Result that = (Result) other;
        return bogon == that.bogon && Objects.equals(raw, that.raw);
    }

    @Override
    public int hashCode() {
        return Objects.hash(raw, bogon);
    }

    @Override
    public String toString() {
        return "Result{ip=" + ip() + ", isVpn=" + isVpn() + ", isBogon=" + bogon + "}";
    }
}
