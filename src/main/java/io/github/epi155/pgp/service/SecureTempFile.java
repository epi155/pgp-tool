package io.github.epi155.pgp.service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.Set;

/**
 * Scratch file whose <b>plaintext never touches the disk</b>.
 *
 * <p>Content is encrypted with ChaCha20-Poly1305 (JCE, JDK 11+) under a
 * random 256-bit <b>session key</b> generated once per JVM launch and kept
 * only in heap memory (zeroed by a shutdown hook). Each file gets its own
 * random 96-bit base nonce (stored in clear in the file header — nonces are
 * public); the per-chunk nonce is {@code base XOR chunkIndex}, so nonces are
 * never reused under the same key.</p>
 *
 * <p>Plaintext is split into fixed 64 KiB chunks, each independently sealed
 * with its own 16-byte Poly1305 tag. This gives streaming writes, sequential
 * reads <i>and</i> random-access slice reads with per-chunk integrity, while
 * presenting plaintext-offset semantics to callers (offsets recorded before
 * encryption stay valid).</p>
 *
 * <p>On-disk layout: {@code [12B nonce][chunk0 ct+tag][chunk1 ct+tag]...}.
 * Chunk {@code i} starts at {@code 12 + i * (65536 + 16)}; the last chunk may
 * be shorter ({@code ctLen - 16} plaintext bytes).</p>
 *
 * <p>Files live in a private {@code 0700} directory and are created
 * {@code 0600} (POSIX, best-effort on other platforms). {@link #wipeAndDelete()}
 * overwrites the ciphertext with zeros before unlinking (best-effort shred
 * against forensic recovery). Orphaned files from a crashed run are unreadable
 * without the previous session key and are swept on next startup.</p>
 */
public class SecureTempFile {

    private static final String CIPHER = "ChaCha20-Poly1305";
    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 16;
    private static final int CHUNK_PLAIN = 65536;
    private static final int CHUNK_CIPHER = CHUNK_PLAIN + TAG_SIZE;
    /** Stale private dirs older than this are swept at startup. */
    private static final long STALE_AGE_MILLIS = 24L * 3600 * 1000;

    private static final Set<PosixFilePermission> FILE_PERMS =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
    private static final Set<PosixFilePermission> DIR_PERMS =
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);

    // ─── Session key (one per JVM launch) ──────────────────────────

    private static final byte[] SESSION_KEY = new byte[KEY_SIZE];
    private static volatile boolean keyReady = false;

    private static synchronized void ensureKey() {
        if (!keyReady) {
            new SecureRandom().nextBytes(SESSION_KEY);
            keyReady = true;
        }
    }

    private static Path secureDir;

    private static synchronized Path dir() throws IOException {
        ensureKey();
        if (secureDir == null) {
            Path base = Path.of(System.getProperty("java.io.tmpdir"));
            sweepStaleDirs(base);
            secureDir = Files.createTempDirectory(base, "pgp-tool-secure-");
            restrict(secureDir, DIR_PERMS);
            secureDir.toFile().deleteOnExit();
            final Path dirToClean = secureDir;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try (DirectoryStream<Path> ds = Files.newDirectoryStream(dirToClean)) {
                    for (Path p : ds) {
                        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
                    }
                } catch (IOException ignored) {}
                try { Files.deleteIfExists(dirToClean); } catch (IOException ignored) {}
                java.util.Arrays.fill(SESSION_KEY, (byte) 0);
            }));
        }
        return secureDir;
    }

    /** Delete previous-run private dirs (their content is unreadable: the key is gone). */
    private static void sweepStaleDirs(Path base) {
        long cutoff = System.currentTimeMillis() - STALE_AGE_MILLIS;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(base, "pgp-tool-secure-*")) {
            for (Path p : ds) {
                try {
                    if (Files.isDirectory(p)
                            && Files.getLastModifiedTime(p).toMillis() < cutoff) {
                        try (DirectoryStream<Path> inner = Files.newDirectoryStream(p)) {
                            for (Path f : inner) {
                                try { Files.deleteIfExists(f); } catch (IOException ignored) {}
                            }
                        }
                        Files.deleteIfExists(p);
                    }
                } catch (IOException ignored) {}
            }
        } catch (IOException ignored) {}
    }

    private static void restrict(Path p, Set<PosixFilePermission> perms) {
        try {
            Files.setPosixFilePermissions(p, perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystem (e.g. Windows): ACLs are inherited from the parent.
        }
    }

    // ─── Instance ──────────────────────────────────────────────────

    private final Path path;
    private final byte[] fileNonce = new byte[NONCE_SIZE];
    private long plaintextSize;

    private SecureTempFile(Path path) {
        this.path = path;
    }

    public static SecureTempFile create(String prefix, String suffix) throws IOException {
        Path p = Files.createTempFile(dir(), prefix, suffix);
        restrict(p, FILE_PERMS);
        p.toFile().deleteOnExit();
        SecureTempFile stf = new SecureTempFile(p);
        stf.reset();
        return stf;
    }

    /** Truncate and start new content with a fresh per-file nonce. */
    private synchronized void reset() throws IOException {
        new SecureRandom().nextBytes(fileNonce);
        plaintextSize = 0;
        try (OutputStream out = Files.newOutputStream(path,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            out.write(fileNonce);
        }
    }

    private byte[] nonceFor(long chunkIndex) {
        byte[] nonce = fileNonce.clone();
        for (int i = 0; i < 8; i++) {
            nonce[NONCE_SIZE - 1 - i] ^= (byte) (chunkIndex >>> (8 * i));
        }
        return nonce;
    }

    private static Cipher newCipher(int mode, byte[] nonce) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(mode, new SecretKeySpec(SESSION_KEY, "ChaCha20"),
                new IvParameterSpec(nonce));
        return cipher;
    }

    // ─── Write ─────────────────────────────────────────────────────

    /**
     * Opens a fresh encrypting stream (truncates previous content).
     * Must be closed before any read.
     */
    public synchronized OutputStream openWrite() throws IOException {
        reset();
        OutputStream fileOut = Files.newOutputStream(path,
                StandardOpenOption.WRITE, StandardOpenOption.APPEND);
        return new EncryptingStream(fileOut);
    }

    private class EncryptingStream extends OutputStream {
        private final OutputStream out;
        private final byte[] buf = new byte[CHUNK_PLAIN];
        private int pos;
        private long chunkIndex;
        private boolean closed;

        EncryptingStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void write(int b) throws IOException {
            buf[pos++] = (byte) b;
            plaintextSize++;
            if (pos == CHUNK_PLAIN) flushChunk();
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            while (len > 0) {
                int n = Math.min(len, CHUNK_PLAIN - pos);
                System.arraycopy(b, off, buf, pos, n);
                pos += n;
                off += n;
                len -= n;
                plaintextSize += n;
                if (pos == CHUNK_PLAIN) flushChunk();
            }
        }

        private void flushChunk() throws IOException {
            seal(buf, 0, pos, chunkIndex++, out);
            pos = 0;
        }

        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            try {
                if (pos > 0) flushChunk();
            } finally {
                out.close();
            }
        }
    }

    private void seal(byte[] plain, int off, int len, long chunkIndex, OutputStream out)
            throws IOException {
        try {
            Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, nonceFor(chunkIndex));
            byte[] sealed = new byte[len + TAG_SIZE];
            int n = cipher.update(plain, off, len, sealed, 0);
            n += cipher.doFinal(sealed, n);
            out.write(sealed, 0, n);
        } catch (GeneralSecurityException e) {
            throw new IOException("SecureTempFile encrypt failed", e);
        }
    }

    // ─── Read ──────────────────────────────────────────────────────

    /** Plaintext length in bytes (valid after the writer is closed). */
    public synchronized long plaintextSize() {
        return plaintextSize;
    }

    /** Sequential decrypting read of the whole content. */
    public InputStream openRead() throws IOException {
        return new DecryptingStream();
    }

    /**
     * Decrypting stream over {@code [offset, offset + length)} (plaintext space).
     * Decrypts chunk by chunk on demand; memory stays bounded by one chunk.
     */
    public synchronized InputStream openSliceRead(long offset, long length) throws IOException {
        long len = length < 0 ? plaintextSize - offset : length;
        if (offset < 0 || len < 0 || offset + len > plaintextSize) {
            throw new IOException("SecureTempFile slice out of range");
        }
        return new SliceStream(offset, len);
    }

    private class SliceStream extends InputStream {
        private final long end;
        private long pos;
        private byte[] current = new byte[0];
        private int currentPos;
        private long currentChunk = -1;

        SliceStream(long offset, long length) {
            this.pos = offset;
            this.end = offset + length;
        }

        @Override
        public int read() throws IOException {
            if (!fill()) return -1;
            pos++;
            return current[currentPos++] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (!fill()) return -1;
            int n = Math.min(len, current.length - currentPos);
            System.arraycopy(current, currentPos, b, off, n);
            currentPos += n;
            pos += n;
            return n;
        }

        private boolean fill() throws IOException {
            if (pos >= end) return false;
            long chunk = pos / CHUNK_PLAIN;
            if (chunk != currentChunk) {
                byte[] full = readChunk(chunk);
                long chunkStart = chunk * CHUNK_PLAIN;
                int from = (int) Math.max(0, pos - chunkStart);
                int to = (int) Math.min(full.length, end - chunkStart);
                current = new byte[to - from];
                System.arraycopy(full, from, current, 0, current.length);
                currentPos = 0;
                currentChunk = chunk;
            } else if (currentPos >= current.length) {
                currentChunk = -1;
                return fill();
            }
            return currentPos < current.length;
        }

        @Override
        public void close() {
            current = new byte[0];
            currentPos = 0;
        }
    }

    private class DecryptingStream extends InputStream {
        private final InputStream in;
        private byte[] current = new byte[0];
        private int pos;
        private long chunkIndex;
        private boolean eof;

        DecryptingStream() throws IOException {
            in = Files.newInputStream(path, StandardOpenOption.READ);
            byte[] header = in.readNBytes(NONCE_SIZE);
            if (header.length != NONCE_SIZE) {
                try { in.close(); } catch (IOException ignored) {}
                throw new IOException("SecureTempFile truncated header");
            }
        }

        @Override
        public int read() throws IOException {
            if (pos >= current.length && !fill()) return -1;
            return current[pos++] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (pos >= current.length && !fill()) return -1;
            int n = Math.min(len, current.length - pos);
            System.arraycopy(current, pos, b, off, n);
            pos += n;
            return n;
        }

        private boolean fill() throws IOException {
            if (eof) return false;
            byte[] sealed = in.readNBytes(CHUNK_CIPHER);
            if (sealed.length == 0) {
                eof = true;
                return false;
            }
            current = open(sealed, 0, sealed.length, chunkIndex++);
            pos = 0;
            return true;
        }

        @Override
        public void close() throws IOException {
            in.close();
        }
    }

    private byte[] open(byte[] sealed, int off, int len, long chunkIndex) throws IOException {
        if (len < TAG_SIZE) throw new IOException("SecureTempFile truncated chunk");
        try {
            Cipher cipher = newCipher(Cipher.DECRYPT_MODE, nonceFor(chunkIndex));
            byte[] plain = new byte[len - TAG_SIZE];
            int n = cipher.update(sealed, off, len, plain, 0);
            n += cipher.doFinal(plain, n);
            if (n != plain.length) throw new IOException("SecureTempFile short decrypt");
            return plain;
        } catch (GeneralSecurityException e) {
            throw new IOException("SecureTempFile integrity check failed", e);
        }
    }

    /** Number of ciphertext chunks currently stored (derived from file size). */
    private long chunkCount() throws IOException {
        long cipherLen = Files.size(path) - NONCE_SIZE;
        if (cipherLen <= 0) return 0;
        return (cipherLen + CHUNK_CIPHER - 1) / CHUNK_CIPHER;
    }

    /** Decrypts a single chunk by index (plaintext offsets stay valid). */
    private byte[] readChunk(long chunkIndex) throws IOException {
        long total = chunkCount();
        if (chunkIndex < 0 || chunkIndex >= total) {
            throw new IOException("SecureTempFile chunk out of range: " + chunkIndex);
        }
        long fileOff = NONCE_SIZE + chunkIndex * CHUNK_CIPHER;
        int toRead;
        if (chunkIndex < total - 1) {
            toRead = CHUNK_CIPHER;
        } else {
            long cipherLen = Files.size(path) - NONCE_SIZE;
            toRead = (int) (cipherLen - chunkIndex * CHUNK_CIPHER);
        }
        byte[] sealed = new byte[toRead];
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "r")) {
            raf.seek(fileOff);
            raf.readFully(sealed);
        }
        return open(sealed, 0, sealed.length, chunkIndex);
    }

    /**
     * Decrypts {@code [offset, offset + length)} (plaintext space).
     */
    public synchronized byte[] readSlice(long offset, long length) throws IOException {
        if (offset < 0 || length < 0 || offset + length > plaintextSize) {
            throw new IOException("SecureTempFile slice out of range");
        }
        if (length > Integer.MAX_VALUE) throw new IOException("SecureTempFile slice too large");
        byte[] result = new byte[(int) length];
        long first = offset / CHUNK_PLAIN;
        long last = length == 0 ? first - 1 : (offset + length - 1) / CHUNK_PLAIN;
        int dest = 0;
        for (long c = first; c <= last; c++) {
            byte[] chunk = readChunk(c);
            long chunkStart = c * CHUNK_PLAIN;
            int from = (int) Math.max(0, offset - chunkStart);
            int to = (int) Math.min(chunk.length, offset + length - chunkStart);
            System.arraycopy(chunk, from, result, dest, to - from);
            dest += to - from;
        }
        return result;
    }

    /** Decrypts the whole content (callers keep the existing ≤50 MB guard). */
    public byte[] readAllPlaintext() throws IOException {
        long size = plaintextSize();
        if (size > Integer.MAX_VALUE) throw new IOException("SecureTempFile too large");
        return readSlice(0, size);
    }

    /** Streams decrypted {@code [offset, offset + length)} (length&lt;0 = to end) to target. */
    public synchronized void copySliceTo(Path target, long offset, long length) throws IOException {
        long len = length < 0 ? plaintextSize - offset : length;
        if (offset < 0 || len < 0 || offset + len > plaintextSize) {
            throw new IOException("SecureTempFile slice out of range");
        }
        try (OutputStream out = Files.newOutputStream(target,
                StandardOpenOption.WRITE, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            long first = len == 0 ? 0 : offset / CHUNK_PLAIN;
            long last = len == 0 ? -1 : (offset + len - 1) / CHUNK_PLAIN;
            for (long c = first; c <= last; c++) {
                byte[] chunk = readChunk(c);
                long chunkStart = c * CHUNK_PLAIN;
                int from = (int) Math.max(0, offset - chunkStart);
                int to = (int) Math.min(chunk.length, offset + len - chunkStart);
                out.write(chunk, from, to - from);
            }
        }
    }

    /** Streams the whole decrypted content to target (overwrites). */
    public void copyDecryptedTo(Path target) throws IOException {
        copySliceTo(target, 0, plaintextSize());
    }

    // ─── Disposal ──────────────────────────────────────────────────

    /**
     * Best-effort shred (single zero pass over the ciphertext) + delete.
     * Safe to call multiple times.
     */
    public synchronized void wipeAndDelete() {
        try {
            long size = Files.size(path);
            try (OutputStream out = Files.newOutputStream(path,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                byte[] zeros = new byte[CHUNK_PLAIN];
                long remaining = size;
                while (remaining > 0) {
                    int n = (int) Math.min(zeros.length, remaining);
                    out.write(zeros, 0, n);
                    remaining -= n;
                }
            } catch (IOException ignored) {}
        } catch (IOException ignored) {}
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {}
    }
}
