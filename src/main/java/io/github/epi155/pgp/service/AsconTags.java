package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import java.security.SecureRandom;

/**
 * Private symmetric tag for the ASCON AEAD (NIST SP 800-232 family).
 *
 * <p>ASCON is an AEAD-only construction (no CFB/stream mode), so the passphrase ESK is wrapped
 * with a proxy AES-CFB cipher ({@link CustomAlgorithms#eskWrapName}). The data packet is a
 * LibrePGP-style AEAD Encrypted Data packet whose {@code aeadAlgorithm} byte must be EAX (1) so
 * that BC derives a 16-byte IV (ASCON uses a 128-bit nonce).</p>
 */
public final class AsconTags {

    public static final int ASCON_128 = 104;

    private AsconTags() {
    }

    public static boolean isAscon(int algorithm) {
        return algorithm == ASCON_128;
    }

    public static int keySizeBits(int algorithm) {
        if (algorithm == ASCON_128) {
            return 128;
        }
        throw new IllegalArgumentException("not an ASCON tag: " + algorithm);
    }

    public static String cipherName() {
        return "Ascon";
    }

    public static int proxyTag(int algorithm) {
        if (algorithm == ASCON_128) {
            return SymmetricKeyAlgorithmTags.AES_128;
        }
        throw new IllegalArgumentException("not an ASCON tag: " + algorithm);
    }

    public static byte[] makeRandomKey(int algorithm, SecureRandom random) {
        byte[] key = new byte[keySizeBits(algorithm) / 8];
        random.nextBytes(key);
        return key;
    }
}
