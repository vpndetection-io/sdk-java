package io.vpndetection;

import java.util.Optional;

/**
 * One address's outcome inside a batch: either its {@link Result} or the failure that address hit.
 *
 * <p>A batch never fails as a whole, so one bad address cannot lose the rest of the answers. Java
 * has no union type, which is why the value is this wrapper rather than a {@code Result} that is
 * sometimes an exception.
 */
public final class BatchResult {
    private final Result result;
    private final VPNDetectionException error;

    private BatchResult(Result result, VPNDetectionException error) {
        this.result = result;
        this.error = error;
    }

    static BatchResult found(Result result) {
        return new BatchResult(result, null);
    }

    static BatchResult failed(VPNDetectionException error) {
        return new BatchResult(null, error);
    }

    public boolean isSuccess() {
        return result != null;
    }

    public Optional<Result> result() {
        return Optional.ofNullable(result);
    }

    public Optional<VPNDetectionException> error() {
        return Optional.ofNullable(error);
    }

    /** The result, or the failure rethrown, for callers that would rather not branch. */
    public Result orElseThrow() {
        if (result == null) {
            throw error;
        }
        return result;
    }

    @Override
    public String toString() {
        return isSuccess() ? "BatchResult{" + result + "}" : "BatchResult{" + error + "}";
    }
}
