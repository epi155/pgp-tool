package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AsconEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * AEAD encryptor/decryptor for the custom symmetric tags (103 = ChaCha20-Poly1305,
 * 100-102 = Serpent-OCB, 104 = ASCON).
 * <p>
 * Emits the LibrePGP-style AEAD Encrypted Data packet (tag 20, version 1) that BouncyCastle 1.84
 * can parse back. The {@code aeadAlgorithm} byte in the packet drives BC's IV length on read
 * ({@code AEADUtils.getIVLength}): GCM (3) -&gt; 12-byte IV for tag 103, OCB (2) -&gt; 15-byte IV for
 * tags 100-102, EAX (1) -&gt; 16-byte IV for tag 104. The actual construction is selected by the
 * symmetric tag: JCE ChaCha20-Poly1305 for 103, lightweight {@link OCBBlockCipher}
 * (SerpentEngine, SerpentEngine) for 100-102, lightweight {@code AsconEngine} (AsconParameters)
 * for 104.
 * <p>
 * No MDC is used: integrity is the AEAD tag, per chunk. Chunk framing is shared across all custom
 * AEAD tags and mirrors the lib-style v5 stream: per-chunk nonce = IV xor chunk index (last 8
 * bytes), AAD = 5-byte packet header plus the 8-byte chunk index (and, for the final tag, the
 * 8-byte total byte count); each chunk is ciphertext + 16-byte tag, followed by a 16-byte final
 * tag that authenticates the total length.
 */
public class CustomAeadEncryptor implements PGPAEADDataEncryptor, PGPDataDecryptor {

    private static final int TAG_LENGTH_BITS = 128;
    private static final int TAG_LENGTH = 16;
    private static final int CHUNK_ENCODED_SIZE = 10; // 2^(10+6) = 64 KiB

    private final int algorithm;
    private final byte[] key;
    private final byte[] iv;
    private final int chunkLength;

    public CustomAeadEncryptor(int algorithm, byte[] sessionKey, SecureRandom random) {
        this.algorithm = algorithm;
        this.key = sessionKey.clone();
        this.iv = new byte[ivLength(algorithm)];
        this.chunkLength = 1 << (CHUNK_ENCODED_SIZE + 6);
        random.nextBytes(iv);
    }

    public CustomAeadEncryptor(int algorithm, byte[] sessionKey, byte[] iv, int encodedChunkSize) {
        this.algorithm = algorithm;
        this.key = sessionKey.clone();
        this.iv = iv.clone();
        this.chunkLength = 1 << (encodedChunkSize + 6);
    }

    @Override
    public int getAEADAlgorithm() {
        return aeadAlgorithm(algorithm);
    }

    @Override
    public int getChunkSize() {
        return CHUNK_ENCODED_SIZE;
    }

    @Override
    public byte[] getIV() {
        return iv.clone();
    }

    @Override
    public OutputStream getOutputStream(OutputStream out) {
        return new AeadEncryptingStream(out);
    }

    @Override
    public InputStream getInputStream(InputStream in) {
        return new AeadDecryptingStream(in);
    }

    @Override
    public int getBlockSize() {
        return 16;
    }

    @Override
    public PGPDigestCalculator getIntegrityCalculator() {
        return null;
    }

    private static int aeadAlgorithm(int algorithm) {
        if (CustomAlgorithms.isChaCha20(algorithm)) {
            return AEADAlgorithmTags.GCM;
        }
        if (AsconTags.isAscon(algorithm)) {
            return AEADAlgorithmTags.EAX;
        }
        return AEADAlgorithmTags.OCB;
    }

    private static int ivLength(int algorithm) {
        if (CustomAlgorithms.isChaCha20(algorithm)) {
            return 12;
        }
        if (AsconTags.isAscon(algorithm)) {
            return 16;
        }
        return 15;
    }

    private byte[] baseAad() {
        return AEADEncDataPacket.createAAData(AEADEncDataPacket.VERSION_1,
                algorithm, aeadAlgorithm(algorithm), CHUNK_ENCODED_SIZE);
    }

    private static byte[] nonce(byte[] iv, long chunkIndex) {
        byte[] n = iv.clone();
        int idx = n.length - 8;
        for (int i = 7; i >= 0; i--) {
            n[idx + i] ^= (byte) (chunkIndex >> (8 * (7 - i)));
        }
        return n;
    }

    private static byte[] aad(byte[] base, long chunkIndex) {
        byte[] a = new byte[base.length + 8];
        System.arraycopy(base, 0, a, 0, base.length);
        System.arraycopy(Pack.longToBigEndian(chunkIndex), 0, a, base.length, 8);
        return a;
    }

    private static int readUpTo(InputStream in, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int r = in.read(buf, off + total, len - total);
            if (r < 0) {
                break;
            }
            total += r;
        }
        return total;
    }

    private interface AeadEngine {
        void init(boolean forEncryption, byte[] nonce) throws IOException;

        void updateAad(byte[] aad) throws IOException;

        /** Process a single input buffer, returning produced bytes (throws on integrity failure). */
        byte[] finish(byte[] in, int off, int len) throws IOException;
    }

    private static AeadEngine newEngine(int algorithm, byte[] key) {
        if (CustomAlgorithms.isChaCha20(algorithm)) {
            try {
                return new JceChaChaEngine(new SecretKeySpec(key, "ChaCha20-Poly1305"));
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Cannot create ChaCha20-Poly1305 cipher", e);
            }
        }
        if (AsconTags.isAscon(algorithm)) {
            return new Ascon128Engine(key);
        }
        return new SerpentOcbEngine(key);
    }

    /** JCE ChaCha20-Poly1305 (tag 103). */
    private static final class JceChaChaEngine implements AeadEngine {

        private final Cipher cipher;
        private final SecretKeySpec keySpec;

        JceChaChaEngine(SecretKeySpec keySpec) throws GeneralSecurityException {
            this.keySpec = keySpec;
            this.cipher = Cipher.getInstance("ChaCha20-Poly1305", "BC");
        }

        @Override
        public void init(boolean forEncryption, byte[] nonce) throws IOException {
            try {
                cipher.init(forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                        keySpec, new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            } catch (GeneralSecurityException e) {
                throw new IOException("ChaCha20-Poly1305 init failed", e);
            }
        }

        @Override
        public void updateAad(byte[] aad) {
            cipher.updateAAD(aad);
        }

        @Override
        public byte[] finish(byte[] in, int off, int len) throws IOException {
            try {
                return cipher.doFinal(in, off, len);
            } catch (GeneralSecurityException e) {
                throw new IOException("ChaCha20-Poly1305 integrity check failed", e);
            }
        }
    }

    /** Lightweight Serpent-OCB3 for tags 100-102. */
    private static final class SerpentOcbEngine implements AeadEngine {

        private final OCBBlockCipher cipher;
        private final KeyParameter key;

        SerpentOcbEngine(byte[] key) {
            this.key = new KeyParameter(key);
            this.cipher = new OCBBlockCipher(new SerpentEngine(), new SerpentEngine());
        }

        @Override
        public void init(boolean forEncryption, byte[] nonce) {
            cipher.init(forEncryption, new AEADParameters(key, TAG_LENGTH_BITS, nonce));
        }

        @Override
        public void updateAad(byte[] aad) {
            cipher.processAADBytes(aad, 0, aad.length);
        }

        @Override
        public byte[] finish(byte[] in, int off, int len) throws IOException {
            byte[] out = new byte[len + TAG_LENGTH];
            int n = cipher.processBytes(in, off, len, out, 0);
            try {
                n += cipher.doFinal(out, n);
            } catch (InvalidCipherTextException e) {
                throw new IOException("Serpent-OCB integrity check failed", e);
            }
            return Arrays.copyOf(out, n);
        }
    }

    /** Lightweight ASCON-128 for tag 104 (NIST SP 800-232 family). */
    private static final class Ascon128Engine implements AeadEngine {

        private final AsconEngine cipher;
        private final KeyParameter key;

        Ascon128Engine(byte[] key) {
            this.key = new KeyParameter(key);
            this.cipher = new AsconEngine(AsconEngine.AsconParameters.ascon128);
        }

        @Override
        public void init(boolean forEncryption, byte[] nonce) {
            cipher.init(forEncryption, new AEADParameters(key, TAG_LENGTH_BITS, nonce));
        }

        @Override
        public void updateAad(byte[] aad) {
            cipher.processAADBytes(aad, 0, aad.length);
        }

        @Override
        public byte[] finish(byte[] in, int off, int len) throws IOException {
            byte[] out = new byte[len + TAG_LENGTH];
            int n = cipher.processBytes(in, off, len, out, 0);
            try {
                n += cipher.doFinal(out, n);
            } catch (InvalidCipherTextException e) {
                throw new IOException("ASCON integrity check failed", e);
            }
            return Arrays.copyOf(out, n);
        }
    }

    private final class AeadEncryptingStream extends OutputStream {

        private final OutputStream out;
        private final AeadEngine engine;
        private final byte[] data;
        private final byte[] aaData;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;
        private boolean closed;

        AeadEncryptingStream(OutputStream out) {
            super();
            this.out = out;
            this.engine = newEngine(algorithm, key);
            this.data = new byte[chunkLength];
            this.aaData = baseAad();
        }

        @Override
        public void write(int b) throws IOException {
            if (dataOff == data.length) {
                writeBlock();
            }
            data[dataOff++] = (byte) b;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (dataOff == data.length) {
                writeBlock();
            }
            if (len < data.length - dataOff) {
                System.arraycopy(b, off, data, dataOff, len);
                dataOff += len;
            } else {
                int gap = data.length - dataOff;
                System.arraycopy(b, off, data, dataOff, gap);
                dataOff += gap;
                writeBlock();
                len -= gap;
                off += gap;
                while (len >= data.length) {
                    System.arraycopy(b, off, data, 0, data.length);
                    dataOff = data.length;
                    writeBlock();
                    len -= data.length;
                    off += data.length;
                }
                if (len > 0) {
                    System.arraycopy(b, off, data, 0, len);
                    dataOff = len;
                }
            }
        }

        @Override
        public void close() throws IOException {
            if (closed) {
                return;
            }
            closed = true;
            if (dataOff > 0) {
                writeBlock();
            }
            engine.init(true, nonce(iv, chunkIndex));
            engine.updateAad(aad(aaData, chunkIndex));
            engine.updateAad(Pack.longToBigEndian(totalBytes));
            byte[] ft = engine.finish(new byte[0], 0, 0);
            out.write(ft);
            out.close();
        }

        private void writeBlock() throws IOException {
            engine.init(true, nonce(iv, chunkIndex));
            engine.updateAad(aad(aaData, chunkIndex));
            byte[] chunk = engine.finish(data, 0, dataOff);
            out.write(chunk);
            totalBytes += dataOff;
            chunkIndex++;
            dataOff = 0;
        }
    }

    private final class AeadDecryptingStream extends InputStream {

        private final InputStream in;
        private final AeadEngine engine;
        private final byte[] buf;
        private final byte[] aaData;
        private byte[] data;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;
        private boolean aeadComplete;

        AeadDecryptingStream(InputStream in) {
            super();
            this.in = in;
            this.engine = newEngine(algorithm, key);
            this.buf = new byte[chunkLength + TAG_LENGTH + TAG_LENGTH];
            this.aaData = baseAad();
            try {
                readUpTo(in, buf, 0, TAG_LENGTH + TAG_LENGTH);
            } catch (IOException e) {
                throw new IllegalStateException("Cannot prime AEAD stream", e);
            }
        }

        @Override
        public int read() throws IOException {
            if (data == null || dataOff == data.length) {
                data = readBlock();
                dataOff = 0;
            }
            if (data == null) {
                return -1;
            }
            return data[dataOff++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            if (data == null || dataOff == data.length) {
                data = readBlock();
                dataOff = 0;
            }
            if (data == null) {
                return -1;
            }
            int n = Math.min(len, data.length - dataOff);
            System.arraycopy(data, dataOff, b, off, n);
            dataOff += n;
            return n;
        }

        private byte[] readBlock() throws IOException {
            int dataLen = readUpTo(in, buf, TAG_LENGTH + TAG_LENGTH, chunkLength);
            if (dataLen == 0) {
                if (!aeadComplete) {
                    verifyFinalTag();
                    aeadComplete = true;
                }
                return null;
            }

            byte[] plain;
            engine.init(false, nonce(iv, chunkIndex));
            engine.updateAad(aad(aaData, chunkIndex));
            plain = engine.finish(buf, 0, dataLen + TAG_LENGTH);
            totalBytes += plain.length;
            chunkIndex++;

            System.arraycopy(buf, dataLen + TAG_LENGTH, buf, 0, TAG_LENGTH);

            if (dataLen != chunkLength) {
                verifyFinalTag();
                aeadComplete = true;
            } else {
                readUpTo(in, buf, TAG_LENGTH, TAG_LENGTH);
            }
            return plain;
        }

        private void verifyFinalTag() throws IOException {
            engine.init(false, nonce(iv, chunkIndex));
            engine.updateAad(aad(aaData, chunkIndex));
            engine.updateAad(Pack.longToBigEndian(totalBytes));
            engine.finish(buf, 0, TAG_LENGTH);
        }
    }
}