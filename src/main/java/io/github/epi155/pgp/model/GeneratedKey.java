package io.github.epi155.pgp.model;

import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.util.ArrayList;
import java.util.List;

public class GeneratedKey {
    private final PGPPublicKeyRing publicKeyRing;
    private final PGPSecretKeyRing secretKeyRing;
    private final PGPKeyPair masterKeyPair;
    private final List<PGPKeyPair> subKeyPairs;

    public GeneratedKey(PGPPublicKeyRing publicKeyRing, PGPSecretKeyRing secretKeyRing,
                        PGPKeyPair masterKeyPair, List<PGPKeyPair> subKeyPairs) {
        this.publicKeyRing = publicKeyRing;
        this.secretKeyRing = secretKeyRing;
        this.masterKeyPair = masterKeyPair;
        this.subKeyPairs = new ArrayList<>(subKeyPairs);
    }

    public PGPPublicKeyRing getPublicKeyRing() { return publicKeyRing; }
    public PGPSecretKeyRing getSecretKeyRing() { return secretKeyRing; }
    public PGPKeyPair getMasterKeyPair() { return masterKeyPair; }
    public List<PGPKeyPair> getSubKeyPairs() { return subKeyPairs; }
}
