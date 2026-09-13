package io.vpndetection;

/**
 * The file formats a licensed database is published in.
 *
 * <p>Which formats a given database is BUILT in is the API's answer, not this enum's: the
 * {@code _provider} catalogs are keyed by provider id, so no MMDB exists for them. Read the
 * list off {@link io.vpndetection.model.DatabaseVersion#getFormats()}.
 */
public enum DatabaseFormat {
    CSVGZ("csvgz"),
    MMDB("mmdb");

    private final String wireValue;

    DatabaseFormat(String wireValue) {
        this.wireValue = wireValue;
    }

    /** The value the API expects, which is the lower-case spelling. */
    public String wireValue() {
        return wireValue;
    }
}
