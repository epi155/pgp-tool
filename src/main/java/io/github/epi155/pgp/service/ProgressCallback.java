package io.github.epi155.pgp.service;

@FunctionalInterface
public interface ProgressCallback {
    void onProgress(int percent, String status);
}
