package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Generator for {@link PacketTags#COMPRESSED_DATA} packets using the custom streaming codec
 * (XZ). Mirrors {@code org.bouncycastle.openpgp.PGPCompressedDataGenerator}, which only
 * accepts IDs 0-3: we write the packet header + algorithm byte, then stream the codec over a
 * non-closing adapter so {@link #close()} can finalise the codec footer and the PGP packet without
 * closing the encrypted output stream beneath (the outer packet owns that).
 */
public final class CustomCompressedDataGenerator {

    private final int algorithm;
    private BCPGOutputStream pkOut;
    private OutputStream dOut;

    public CustomCompressedDataGenerator(int algorithm) {
        if (!CustomCompression.isCustom(algorithm)) {
            throw new IllegalArgumentException("not a custom compression algorithm: " + algorithm);
        }
        this.algorithm = algorithm;
    }

    public OutputStream open(OutputStream out) throws IOException {
        if (dOut != null) {
            throw new IllegalStateException("generator already in open state");
        }
        this.pkOut = new BCPGOutputStream(out, PacketTags.COMPRESSED_DATA);
        pkOut.write(algorithm);
        this.dOut = CustomCompression.compress(new NonClosingOutputStream(pkOut), algorithm);
        return new WrappedGeneratorStream(dOut, this);
    }

    public void close() throws IOException {
        if (dOut != null) {
            dOut.close();
            dOut = null;
            pkOut.finish();
            pkOut.flush();
            pkOut = null;
        }
    }

    /** The codec streams call {@code close()} on the stream they were built over; this keeps the packet open. */
    private static final class NonClosingOutputStream extends OutputStream {
        private final OutputStream out;

        NonClosingOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
        }
    }

    private static final class WrappedGeneratorStream extends FilterOutputStream {
        private final CustomCompressedDataGenerator generator;

        WrappedGeneratorStream(OutputStream out, CustomCompressedDataGenerator generator) {
            super(out);
            this.generator = generator;
        }

        @Override
        public void close() throws IOException {
            generator.close();
        }
    }
}