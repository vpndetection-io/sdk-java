package io.vpndetection;

import io.vpndetection.model.AbuseContact;
import io.vpndetection.model.Asn;
import io.vpndetection.model.BitTorrentDetail;
import io.vpndetection.model.BotDetail;
import io.vpndetection.model.CarrierDetail;
import io.vpndetection.model.ClassDetail;
import io.vpndetection.model.Company;
import io.vpndetection.model.DnsResolverDetail;
import io.vpndetection.model.Location;
import io.vpndetection.model.LookupResponse;
import io.vpndetection.model.ProxyDetail;
import io.vpndetection.model.PubproxyDetail;
import io.vpndetection.model.SatelliteDetail;
import io.vpndetection.model.SmtpDetail;
import io.vpndetection.model.SshDetail;
import io.vpndetection.model.VpnDetail;
import io.vpndetection.model.WebDetail;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
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
 * <p>A detail object that is present but empty ({@link #web()}'s empty list) means the flag above
 * it is false. A populated one always carries every one of its keys.
 */
public final class Result {
    private final LookupResponse raw;
    private final boolean bogon;

    private Result(LookupResponse raw, boolean bogon) {
        this.raw = raw;
        this.bogon = bogon;
    }

    static Result of(LookupResponse body) {
        return new Result(body, Boolean.TRUE.equals(body.getIsBogon()));
    }

    /**
     * The answer a bogon gets, in the full shape the API serves at its widest plan: {@link
     * #isBogon()} true and every other flag present and false, every detail object present and
     * empty, and the location and AS with every field empty, as the API answers a bogon.
     *
     * <p>Note this is deliberately the WIDEST shape regardless of your plan, so do not infer which
     * fields your plan includes from a bogon answer.
     */
    static Result bogon(String ip) {
        LookupResponse r = new LookupResponse()
                .ip(ip)
                .isBogon(true)
                .isVpn(false)
                .isHosting(false)
                .isRelay(false)
                .isTor(false)
                .isCdn(false)
                .isBot(false)
                .isResproxy(false)
                .isDcproxy(false)
                .isMobproxy(false)
                .isPubproxy(false)
                .isAnycast(false)
                .isCarrier(false)
                .isSatellite(false)
                .isSsh(false)
                .isSmtp(false)
                .isWeb(false)
                .isDnsResolver(false)
                .isBittorrent(false)
                .vpn(new VpnDetail())
                .hosting(new ClassDetail())
                .relay(new ClassDetail())
                .tor(new ClassDetail())
                .cdn(new ClassDetail())
                .bot(new BotDetail())
                .resproxy(new ProxyDetail())
                .dcproxy(new ProxyDetail())
                .mobproxy(new ProxyDetail())
                .pubproxy(new PubproxyDetail())
                .carrier(new CarrierDetail())
                .satellite(new SatelliteDetail())
                .ssh(new SshDetail())
                .smtp(new SmtpDetail())
                .web(new ArrayList<>())
                .dnsResolver(new DnsResolverDetail())
                .bittorrent(new BitTorrentDetail())
                .location(new Location()
                        .continent("")
                        .continentName("")
                        .country("")
                        .countryName("")
                        .timezone("")
                        .currencyCode("")
                        .currencyName("")
                        .currencySymbol("")
                        .flagEmoji("")
                        .flagUnicode("")
                        .region("")
                        .regionCode("")
                        .city("")
                        .postalCode("")
                        .latitude(BigDecimal.ZERO)
                        .longitude(BigDecimal.ZERO)
                        .accuracyRadius(0)
                        .geonameId("")
                        .dmaCode("")
                        .lastChanged(""))
                .asn(new Asn().asn(0L).name("").domain("").type("").prefix("").country("").rpkiStatus(""))
                .company(new Company().name("").domain("").type("").country(""))
                .hostname("")
                .abuse(new AbuseContact()
                        .email("")
                        .name("")
                        .phone("")
                        .address("")
                        .country("")
                        .network("")
                        .validated(false)
                        .unvalidatedSince(""));
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

    /**
     * True for reserved space (private, loopback, documentation and the like), which the client
     * answers locally without a request. A served answer carries the API's own {@code is_bogon},
     * and this reads it.
     */
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

    /**
     * Whether an automated client uses the address: a search engine's or an AI company's crawler, an
     * uptime monitor, an internet scanner or a webhook sender. On every answer, with or without a key.
     */
    public Optional<Boolean> isBot() {
        return Optional.ofNullable(raw.getIsBot());
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

    /**
     * Whether a public proxy, one anyone can connect through, listens on the address or sends its
     * traffic out from it. Scale and above.
     */
    public Optional<Boolean> isPubproxy() {
        return Optional.ofNullable(raw.getIsPubproxy());
    }

    /**
     * Whether the address is announced from many places at once, as a public DNS resolver's or a
     * CDN's edge is. On every answer, with or without a key.
     */
    public Optional<Boolean> isAnycast() {
        return Optional.ofNullable(raw.getIsAnycast());
    }

    /** Whether the address is a mobile carrier's, where many phones can share one address. On every paid plan. */
    public Optional<Boolean> isCarrier() {
        return Optional.ofNullable(raw.getIsCarrier());
    }

    /** Whether the address is a satellite operator's. On every paid plan. */
    public Optional<Boolean> isSatellite() {
        return Optional.ofNullable(raw.getIsSatellite());
    }

    /** Whether an SSH server answered on the address. On every paid plan. */
    public Optional<Boolean> isSsh() {
        return Optional.ofNullable(raw.getIsSsh());
    }

    /** Whether a mail server answered on the address. On every paid plan. */
    public Optional<Boolean> isSmtp() {
        return Optional.ofNullable(raw.getIsSmtp());
    }

    /** Whether a web server answered on the address, on port 80 or 443. On every paid plan. */
    public Optional<Boolean> isWeb() {
        return Optional.ofNullable(raw.getIsWeb());
    }

    /** Whether an open DNS resolver answered on the address. On every paid plan. */
    public Optional<Boolean> isDnsResolver() {
        return Optional.ofNullable(raw.getIsDnsResolver());
    }

    /** Whether a BitTorrent client was seen on the address in the last 90 days. On every paid plan. */
    public Optional<Boolean> isBittorrent() {
        return Optional.ofNullable(raw.getIsBittorrent());
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

    /**
     * Detail for {@link #isBot()}: whose bot uses the address, the bots it serves, what they do and
     * whether the operator vouches for the address. Empty when it is false. On every paid plan.
     */
    public Optional<BotDetail> bot() {
        return Optional.ofNullable(raw.getBot());
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
     * Detail for {@link #isPubproxy()}: which end of a proxy the address is, its protocols, and how
     * many ports and proxies it counts at each end. On every paid plan.
     */
    public Optional<PubproxyDetail> pubproxy() {
        return Optional.ofNullable(raw.getPubproxy());
    }

    /** Detail for {@link #isCarrier()}. Empty when it is false. On every paid plan. */
    public Optional<CarrierDetail> carrier() {
        return Optional.ofNullable(raw.getCarrier());
    }

    /** Detail for {@link #isSatellite()}. Empty when it is false. On every paid plan. */
    public Optional<SatelliteDetail> satellite() {
        return Optional.ofNullable(raw.getSatellite());
    }

    /** Detail for {@link #isSsh()}. Empty when it is false. On every paid plan. */
    public Optional<SshDetail> ssh() {
        return Optional.ofNullable(raw.getSsh());
    }

    /** Detail for {@link #isSmtp()}. Empty when it is false. On every paid plan. */
    public Optional<SmtpDetail> smtp() {
        return Optional.ofNullable(raw.getSmtp());
    }

    /**
     * Detail for {@link #isWeb()}: a row per port that answered, lowest first, and an empty list
     * when it is false. On every paid plan.
     */
    public Optional<List<WebDetail>> web() {
        return Optional.ofNullable(raw.getWeb());
    }

    /** Detail for {@link #isDnsResolver()}. Empty when it is false. On every paid plan. */
    public Optional<DnsResolverDetail> dnsResolver() {
        return Optional.ofNullable(raw.getDnsResolver());
    }

    /** Detail for {@link #isBittorrent()}. Empty when it is false. On every paid plan. */
    public Optional<BitTorrentDetail> bittorrent() {
        return Optional.ofNullable(raw.getBittorrent());
    }

    /**
     * Where the address is, on every answer, with or without a key: the country and its currency on
     * every plan, and the region, city and coordinates on a paid one, null on a plan without them.
     * A field your plan includes is an empty string or zero where it is not known.
     */
    public Optional<Location> location() {
        return Optional.ofNullable(raw.getLocation());
    }

    /**
     * The AS announcing the address, on every answer, with or without a key, its country and RPKI
     * status included: 0 where none does.
     */
    public Optional<Asn> asn() {
        return Optional.ofNullable(raw.getAsn());
    }

    /** The organization the address belongs to. On every paid plan. */
    public Optional<Company> company() {
        return Optional.ofNullable(raw.getCompany());
    }

    /**
     * The name the address's reverse DNS (PTR) record points to, empty when it has none. On every
     * answer, with or without a key.
     */
    public Optional<String> hostname() {
        return Optional.ofNullable(raw.getHostname());
    }

    /** Where to report abuse from the address. On every paid plan. */
    public Optional<AbuseContact> abuse() {
        return Optional.ofNullable(raw.getAbuse());
    }

    /**
     * On answers to a key on the free plan only: {@code false} while its organization's trial of
     * every field lasts, {@code true} once the answer has Unlimited's.
     */
    public Optional<Boolean> trialExpired() {
        return Optional.ofNullable(raw.getTrialExpired());
    }

    /**
     * On answers to a key on a paid plan only: {@code false} while the answer has every field,
     * {@code true} once its organization's overage cap is reached and the answer has Unlimited's.
     * Lookups answered past the cap are not billed.
     */
    public Optional<Boolean> capReached() {
        return Optional.ofNullable(raw.getCapReached());
    }

    /**
     * The response exactly as it came off the wire, with its original names.
     *
     * <p>For a bogon this is synthesized locally rather than served.
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
