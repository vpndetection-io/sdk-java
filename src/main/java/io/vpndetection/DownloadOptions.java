package io.vpndetection;

/**
 * Which file one {@link DatabaseApi} download fetches. Left unset, the build that is live.
 */
public class DownloadOptions {
    private String build;

    /**
     * One build of the dataset, by the name a {@code database.updated} webhook gives it, so the file
     * is the one whose {@code sha256} the webhook carries. A build is kept 7 days; one pruned since
     * is a {@link ErrorKind#BAD_REQUEST} with status 410, sent once.
     */
    public DownloadOptions build(String build) {
        this.build = build;
        return this;
    }

    String buildOrNull() {
        return build;
    }
}
