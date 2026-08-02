package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import java.security.SecureRandom;

public final class SerpentTags {

    public static final int SERPENT_128 = 100;
    public static final int SERPENT_192 = 101;
    public static final int SERPENT_256 = 102;

    private SerpentTags() {
    }

    public static boolean isSerpent(int algorithm) {
        return algorithm >= SERPENT_128 && algorithm <= SERPENT_256;
    }

    public static int keySizeBits(int algorithm) {
        switch (algorithm) {
            case SERPENT_128:
                return 128;
            case SERPENT_192:
                return 192;
            case SERPENT_256:
                return 256;
            default:
                throw new IllegalArgumentException("not a Serpent tag: " + algorithm);
        }
    }

    public static String cipherName() {
        return "Serpent";
    }

    public static int proxyTag(int algorithm) {
        switch (algorithm) {
            case SERPENT_128:
                return SymmetricKeyAlgorithmTags.AES_128;
            case SERPENT_192:
                return SymmetricKeyAlgorithmTags.AES_192;
            case SERPENT_256:
                return SymmetricKeyAlgorithmTags.AES_256;
            default:
                throw new IllegalArgumentException("not a Serpent tag: " + algorithm);
        }
    }

    public static byte[] makeRandomKey(int algorithm, SecureRandom random) {
        byte[] key = new byte[keySizeBits(algorithm) / 8];
        random.nextBytes(key);
        return key;
    }
}
