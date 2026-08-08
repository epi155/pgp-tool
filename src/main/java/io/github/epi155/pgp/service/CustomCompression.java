package io.github.epi155.pgp.service;

import com.github.luben.zstd.ZstdInputStream;
import com.github.luben.zstd.ZstdOutputStream;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZInputStream;
import org.tukaani.xz.XZOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Streaming-compression codecs for the PGP compressed-data packet (tag 8).
 * <p>
 * BC only understands algorithm IDs 0-3 ({@code CompressionAlgorithmTags}, ZIP/ZLIB/BZIP2 and
 * UNCOMPRESSED). This dispatcher adds private-use IDs in the 128-255 range, mirroring the custom
 * symmetric-cipher extension: 128 = XZ (Streaming {@code org.tukaani.xz} LZMA2), 129 = ZSTD
 * (Zstandard, {@code com.github.luben:zstd-jni} which bundles natives for both Linux and Windows).
 * Both are true streaming codecs, so they fit the single-stream PGP compressed-data packet.
 * </p><p>
 * These are custom, non-interoperable: gpg/other tools will not recognise the algorithm byte and
 * cannot decrypt messages compressed with them (consistent with the custom AEAD ciphers).
 * </p>
 */
public final class CustomCompression {

    public static final int XZ = 128;
    public static final int ZSTD = 129;

    private CustomCompression() {
    }

    public static boolean isCustom(int algorithm) {
        return algorithm == XZ || algorithm == ZSTD;
    }

    public static String name(int algorithm) {
        switch (algorithm) {
            case XZ:
                return "XZ";
            case ZSTD:
                return "ZSTD";
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }

    public static OutputStream compress(OutputStream out, int algorithm) throws IOException {
        switch (algorithm) {
            case XZ:
                return new XZOutputStream(out, new LZMA2Options());
            case ZSTD:
                return new ZstdOutputStream(out, 7);
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }

    public static InputStream decompress(InputStream in, int algorithm) throws IOException {
        switch (algorithm) {
            case XZ:
                return new XZInputStream(in);
            case ZSTD:
                return new ZstdInputStream(in);
            default:
                throw new IllegalArgumentException("not a custom compression tag: " + algorithm);
        }
    }
}