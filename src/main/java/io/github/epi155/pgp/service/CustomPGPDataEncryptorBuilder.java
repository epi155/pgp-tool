package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;

public class CustomPGPDataEncryptorBuilder implements PGPDataEncryptorBuilder {

    private final int algorithm;
    private final SecureRandom secureRandom;
    private boolean withIntegrityPacket = true;

    public CustomPGPDataEncryptorBuilder(int algorithm) {
        if (!CustomAlgorithms.isCustom(algorithm)) {
            throw new IllegalArgumentException("not a custom tag: " + algorithm);
        }
        this.algorithm = algorithm;
        this.secureRandom = new SecureRandom();
    }

    public CustomPGPDataEncryptorBuilder(int algorithm, SecureRandom secureRandom) {
        if (!CustomAlgorithms.isCustom(algorithm)) {
            throw new IllegalArgumentException("not a custom tag: " + algorithm);
        }
        this.algorithm = algorithm;
        this.secureRandom = secureRandom;
    }

    @Override
    public int getAlgorithm() {
        return algorithm;
    }

    @Override
    public int getAeadAlgorithm() {
        return -1;
    }

    @Override
    public int getChunkSize() {
        return 0;
    }

    @Override
    public boolean isV5StyleAEAD() {
        return false;
    }

    @Override
    public PGPDataEncryptor build(byte[] sessionKey) throws PGPException {
        if (CustomAlgorithms.isAead(algorithm)) {
            return new CustomAeadEncryptor(algorithm, sessionKey, secureRandom);
        }
        return new CustomPGPDataEncryptor(algorithm, sessionKey, Cipher.ENCRYPT_MODE, withIntegrityPacket);
    }

    @Override
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    @Override
    public PGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket) {
        this.withIntegrityPacket = withIntegrityPacket;
        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize) {
        throw new UnsupportedOperationException("AEAD not supported for custom algorithms");
    }

    @Override
    public PGPDataEncryptorBuilder setUseV5AEAD() {
        throw new UnsupportedOperationException("AEAD not supported for custom algorithms");
    }

    @Override
    public PGPDataEncryptorBuilder setUseV6AEAD() {
        throw new UnsupportedOperationException("AEAD not supported for custom algorithms");
    }

    /**
     * Legacy CFB+MDC data decryptor for the custom tags (100-102 Serpent, reached only for old
     * SEIPD v1 messages written before the tags switched to AEAD-OCB).
     *
     * @deprecated Read-only fallback for Serpent-CFB messages. New writes emit AEAD-OCB (tag 20 v1,
     *             no MDC) via {@link CustomAeadEncryptor}. Scheduled for removal around August 2027.
     */
@Deprecated
    public static PGPDataDecryptor createDataDecryptor(int algorithm, boolean integrityPacket, byte[] sessionKey) throws PGPException {
        warnLegacyCfb();
        return new CustomPGPDataEncryptor(algorithm, sessionKey, Cipher.DECRYPT_MODE, integrityPacket);
    }

    private static final AtomicBoolean legacyCfbWarned = new AtomicBoolean(false);

    private static void warnLegacyCfb() {
        if (legacyCfbWarned.compareAndSet(false, true)) {
            System.err.println("WARNING: decoding a legacy Serpent-CFB message (SEIPD v1 + MDC). "
                    + "This read-only fallback is deprecated and may be removed after August 2027.");
        }
    }

    /**
     * @deprecated Legacy CFB+MDC mode; superceded by AEAD-OCB. Scheduled for removal around August 2027.
     */
    @Deprecated
    private static class CustomPGPDataEncryptor implements PGPDataEncryptor, PGPDataDecryptor {

        private final Cipher cipher;
        private final SecretKeySpec keySpec;
        private final boolean withIntegrityPacket;

        CustomPGPDataEncryptor(int algorithm, byte[] sessionKey, int mode, boolean withIntegrityPacket) throws PGPException {
            this.withIntegrityPacket = withIntegrityPacket;
            String name = CustomAlgorithms.jceCipherName(algorithm);
            String transformation = name + "/CFB/NoPadding";
            try {
                keySpec = new SecretKeySpec(sessionKey, name);
                cipher = Cipher.getInstance(transformation, "BC");
                cipher.init(mode, keySpec, CustomAlgorithms.makeIv(algorithm));
            } catch (Exception e) {
                throw new PGPException("Exception creating custom cipher", e);
            }
        }

        @Override
        public OutputStream getOutputStream(OutputStream out) {
            return new CipherOutputStream(out, cipher);
        }

        @Override
        public InputStream getInputStream(InputStream in) {
            return new CipherInputStream(in, cipher);
        }

        @Override
        public PGPDigestCalculator getIntegrityCalculator() {
            if (!withIntegrityPacket) {
                return null;
            }
            try {
                return new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
            } catch (PGPException e) {
                throw new IllegalStateException("Exception creating SHA-1 digest calculator", e);
            }
        }

        @Override
        public int getBlockSize() {
            return 16;
        }
    }
}
