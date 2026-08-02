package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public final class CustomAlgorithms {

    public static final int CHACHA20_POLY1305 = 103;

    private CustomAlgorithms() {
    }

    public static boolean isCustom(int algorithm) {
        return SerpentTags.isSerpent(algorithm) || algorithm == CHACHA20_POLY1305;
    }

    public static boolean isChaCha20(int algorithm) {
        return algorithm == CHACHA20_POLY1305;
    }

    public static boolean isAead(int algorithm) {
        return algorithm == CHACHA20_POLY1305 || SerpentTags.isSerpent(algorithm);
    }

    public static int keySizeBytes(int algorithm) {
        if (SerpentTags.isSerpent(algorithm)) {
            return SerpentTags.keySizeBits(algorithm) / 8;
        }
        if (algorithm == CHACHA20_POLY1305) {
            return 32;
        }
        throw new IllegalArgumentException("not a custom tag: " + algorithm);
    }

    public static int blockSize(int algorithm) {
        if (isCustom(algorithm)) {
            return 16;
        }
        throw new IllegalArgumentException("not a custom tag: " + algorithm);
    }

    public static String jceCipherName(int algorithm) {
        if (SerpentTags.isSerpent(algorithm)) {
            return "Serpent";
        }
        if (algorithm == CHACHA20_POLY1305) {
            return "CHACHA7539";
        }
        throw new IllegalArgumentException("not a custom tag: " + algorithm);
    }

    public static int proxyTag(int algorithm) {
        if (SerpentTags.isSerpent(algorithm)) {
            return SerpentTags.proxyTag(algorithm);
        }
        if (algorithm == CHACHA20_POLY1305) {
            return SymmetricKeyAlgorithmTags.AES_256;
        }
        throw new IllegalArgumentException("not a custom tag: " + algorithm);
    }

    public static String displayName(int algorithm) {
        if (SerpentTags.isSerpent(algorithm)) {
            switch (algorithm) {
                case SerpentTags.SERPENT_128:
                    return "Serpent-128";
                case SerpentTags.SERPENT_192:
                    return "Serpent-192";
                default:
                    return "Serpent-256";
            }
        }
        if (algorithm == CHACHA20_POLY1305) {
            return "ChaCha20-Poly1305";
        }
        throw new IllegalArgumentException("not a custom tag: " + algorithm);
    }

    public static byte[] makeRandomKey(int algorithm, SecureRandom random) {
        byte[] key = new byte[keySizeBytes(algorithm)];
        random.nextBytes(key);
        return key;
    }

    public static IvParameterSpec makeIv(int algorithm) {
        return new IvParameterSpec(new byte[isChaCha20(algorithm) ? 12 : 16]);
    }
}
