package io.vpndetection;

/** The file formats a licensed dataset is published in. */
public enum DatasetFormat {
    CSVGZ("csvgz"),
    MMDB("mmdb");

    private final String wireValue;

    DatasetFormat(String wireValue) {
        this.wireValue = wireValue;
    }

    /** The value the API expects, which is the lower-case spelling. */
    public String wireValue() {
        return wireValue;
    }
}
