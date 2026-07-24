package com.example.pgp.service;

@FunctionalInterface
public interface ProgressCallback {
    void onProgress(int percent, String status);
}
