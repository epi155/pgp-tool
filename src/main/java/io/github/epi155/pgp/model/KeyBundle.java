package io.github.epi155.pgp.model;

import java.util.List;

public class KeyBundle {
    private final List<PGPKeyInfo> keys;
    private final String sourceFile;

    public KeyBundle(List<PGPKeyInfo> keys, String sourceFile) {
        this.keys = keys;
        this.sourceFile = sourceFile;
    }

    public List<PGPKeyInfo> getKeys() { return keys; }
    public String getSourceFile() { return sourceFile; }
}
