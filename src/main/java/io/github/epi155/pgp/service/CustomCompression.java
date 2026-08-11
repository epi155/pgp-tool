package io.github.epi155.pgp.service;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZInputStream;
import org.tukaani.xz.XZOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Streaming-compression codec for the PGP compressed-data packet (tag 8).
 * <p>
 * BC only understands algorithm IDs 0-3 ({@code CompressionAlgorithmTags}, ZIP/ZLIB/BZIP2 and
 * UNCOMPRESSED). This dispatcher adds a private-use ID in the 128-255 range, mirroring the custom
 * symmetric-cipher extension: 128 = XZ (Streaming {@code org.tukaani.xz} LZMA2). 129 (ZSTD) was
 * removed: the JNI {@code zstd-jni} native limited the fat jar to x86_64 Linux/Windows for little
 * practical gain over XZ. Messages compressed with tag 129 by older builds are no longer readable.
 * </p><p>
 * These are custom, non-interoperable: gpg/other tools will not recognise the algorithm byte and
 * cannot decrypt messages compressed with them (consistent with the custom AEAD ciphers).
 * </p>
 */
public final class CustomCompression {

    public static final int XZ = 128;

    private CustomCompression() {
    }

    public static boolean isCustom(int algorithm) {
        return algorithm == XZ;
    }

    public static String name(int algorithm) {
        switch (algorithm) {
            case XZ:
                return "XZ";
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }

    public static OutputStream compress(OutputStream out, int algorithm) throws IOException {
        switch (algorithm) {
            case XZ:
                return new XZOutputStream(out, new LZMA2Options());
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }

    public static InputStream decompress(InputStream in, int algorithm) throws IOException {
        switch (algorithm) {
            case XZ:
                return new XZInputStream(in);
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }
}