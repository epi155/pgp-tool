package io.github.epi155.pgp.model;

import io.github.epi155.pgp.service.SecureTempFile;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class TarCodec {

    private static final byte[] MAGIC = {'P', 'G', 'P', 'C'};
    private static final int VERSION = 3; // v3 = tar format

    public static byte[] encode(TarArchive archive) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        encode(archive, buf);
        return buf.toByteArray();
    }

    public static void encode(TarArchive archive, OutputStream out) throws IOException {
        DataOutputStream dataOut = new DataOutputStream(out);

        dataOut.write(MAGIC);
        dataOut.writeByte(VERSION);

        int numParts = 1;
        if (archive.hasAttachments()) numParts++;
        dataOut.writeInt(numParts);

        String plainText = archive.getPlainText();
        byte[] textBytes = plainText != null ? plainText.getBytes(StandardCharsets.UTF_8) : new byte[0];
        dataOut.writeByte(0);
        dataOut.writeInt(0);
        dataOut.writeLong(textBytes.length);
        dataOut.write(textBytes);

        if (archive.hasAttachments()) {
            // The tar staging area holds plaintext: keep it session-encrypted on disk.
            SecureTempFile tempFile = SecureTempFile.create("tar-", ".tar");
            try {
                long tarSize;
                try (OutputStream tarOut = tempFile.openWrite()) {
                    archive.writeTo(tarOut);
                }
                tarSize = tempFile.plaintextSize();

                byte[] nameBytes = archive.getTarFileName().getBytes(StandardCharsets.UTF_8);
                dataOut.writeByte(1);
                dataOut.writeInt(nameBytes.length);
                dataOut.write(nameBytes);
                dataOut.writeLong(tarSize);
                byte[] buf = new byte[8192];
                try (InputStream tarIn = tempFile.openRead()) {
                    int n;
                    while ((n = tarIn.read(buf)) >= 0) {
                        dataOut.write(buf, 0, n);
                    }
                }
            } finally {
                tempFile.wipeAndDelete();
            }
        }

        dataOut.flush();
    }

    public static TarArchive decode(InputStream in, SecureTempFile tempFile) throws IOException {
        DataInputStream dataIn = new DataInputStream(in);

        byte[] magic = new byte[4];
        dataIn.readFully(magic);
        for (int i = 0; i < 4; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IOException("Not a PGPC compound message");
            }
        }

        int version = dataIn.readUnsignedByte();
        if (version != 1 && version != VERSION) {
            throw new IOException("Unsupported PGPC version: " + version);
        }

        // For v1, delegate to CompoundCodec
        if (version == 1) {
            // Need to re-read from beginning - create a new stream with the data we already read
            // For simplicity, we'll handle this by reading the rest and prepending what we read
            // Actually, CompoundCodec expects to read from the start, so we need a different approach
            // Let's read all remaining data and prepend the header
            ByteArrayOutputStream fullBuf = new ByteArrayOutputStream();
            fullBuf.write(magic);
            fullBuf.write(version);
            byte[] rest = dataIn.readAllBytes();
            fullBuf.write(rest);
            CompoundMessage compound = CompoundCodec.decode(new ByteArrayInputStream(fullBuf.toByteArray()), tempFile);
            // Convert CompoundMessage to TarArchive
            return toTarArchive(compound);
        }

        // v3: tar format
        int numParts = dataIn.readInt();
        String plainText = null;
        TarArchive archive = new TarArchive();

        for (int i = 0; i < numParts; i++) {
            int type = dataIn.readUnsignedByte();
            int filenameLen = dataIn.readInt();
            String filename = "";
            if (filenameLen > 0) {
                byte[] nameBytes = new byte[filenameLen];
                dataIn.readFully(nameBytes);
                filename = new String(nameBytes, StandardCharsets.UTF_8);
            }
            long contentLen = dataIn.readLong();
            if (contentLen > Integer.MAX_VALUE) {
                throw new IOException("Part too large: " + contentLen);
            }
            int contentLenInt = (int) contentLen;

            if (type == 0 && filenameLen == 0) {
                // Text part
                byte[] content = new byte[contentLenInt];
                dataIn.readFully(content);
                plainText = new String(content, StandardCharsets.UTF_8);
            } else {
                // Binary part - should be tar archive
                if (tempFile != null) {
                    // Stage tar content session-encrypted for streaming decode
                    SecureTempFile tarTempFile = SecureTempFile.create("tar-", ".tar");
                    try (OutputStream tarOut = tarTempFile.openWrite()) {
                        byte[] buf = new byte[8192];
                        long remaining = contentLen;
                        while (remaining > 0) {
                            int toRead = (int) Math.min(buf.length, remaining);
                            int n = dataIn.read(buf, 0, toRead);
                            if (n < 0) throw new IOException("Unexpected EOF reading tar content");
                            tarOut.write(buf, 0, n);
                            remaining -= n;
                        }
                    }

                    // Decode tar from the encrypted staging file
                    try (InputStream tarIn = tarTempFile.openRead()) {
                        archive = decodeTar(tarIn);
                    } finally {
                        tarTempFile.wipeAndDelete();
                    }
                } else {
                    byte[] tarBytes = new byte[contentLenInt];
                    dataIn.readFully(tarBytes);
                    try (InputStream tarIn = new ByteArrayInputStream(tarBytes)) {
                        archive = decodeTar(tarIn);
                    }
                }
            }
        }

        if (plainText == null) plainText = "";
        archive.setPlainText(plainText);
        return archive;
    }

    /** Converts a legacy v1 compound message to a tar archive (one entry per attachment). */
    public static TarArchive toTarArchive(CompoundMessage compound) {
        TarArchive archive = new TarArchive();
        archive.setPlainText(compound.getPlainText());
        for (CompoundMessage.Attachment att : compound.getAttachments()) {
            if (att.getTempFile() != null) {
                // Slice-backed: no heap materialization, offsets are plaintext-space.
                long len = att.getLength() >= 0
                        ? att.getLength() : att.getTempFile().plaintextSize() - att.getOffset();
                TarArchiveEntry raw = new TarArchiveEntry(att.getFilename());
                raw.setSize(len);
                TarEntry entry = new TarEntry(raw, att.getTempFile(), att.getOffset(), len);
                entry.setModificationTime(att.getModificationTime());
                archive.addEntry(entry);
            } else {
                TarEntry entry = new TarEntry(att.getFilename(), att.getContent(), att.getModificationTime());
                archive.addEntry(entry);
            }
        }
        return archive;
    }

    private static TarArchive decodeTar(InputStream in) throws IOException {
        TarArchive archive = new TarArchive();
        try (TarArchiveInputStream tarIn = new TarArchiveInputStream(in)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                long size = entry.getSize();
                if (entry.isSymbolicLink()) {
                    byte[] content = new byte[(int) size];
                    readFully(tarIn, content, entry.getName());
                    String linkTarget = new String(content, StandardCharsets.UTF_8);
                    TarEntry tarEntry = new TarEntry(entry);
                    tarEntry.setLinkName(linkTarget);
                    tarEntry.setSize(linkTarget.length());
                    archive.addEntry(tarEntry);
                } else if (size <= 50_000_000) {
                    byte[] content = new byte[(int) size];
                    readFully(tarIn, content, entry.getName());
                    TarEntry tarEntry = new TarEntry(entry.getName(), content, entry.getModTime().getTime());
                    tarEntry.setMode(entry.getMode());
                    tarEntry.setUserName(entry.getUserName());
                    tarEntry.setGroupName(entry.getGroupName());
                    tarEntry.setUserId(entry.getLongUserId());
                    tarEntry.setGroupId(entry.getLongGroupId());
                    if (entry.getLinkName() != null && !entry.getLinkName().isEmpty()) {
                        tarEntry.setLinkName(entry.getLinkName());
                    }
                    archive.addEntry(tarEntry);
                } else {
                    // Large entry: stage it session-encrypted instead of materializing
                    // it in heap, and reference it as a slice (memory stays bounded).
                    SecureTempFile staging = SecureTempFile.create("tar-big-", ".bin");
                    try (OutputStream entryOut = staging.openWrite()) {
                        byte[] buf = new byte[8192];
                        long remaining = size;
                        while (remaining > 0) {
                            int toRead = (int) Math.min(buf.length, remaining);
                            int n = tarIn.read(buf, 0, toRead);
                            if (n < 0) {
                                throw new IOException("Incomplete read for entry: " + entry.getName());
                            }
                            entryOut.write(buf, 0, n);
                            remaining -= n;
                        }
                    } catch (IOException | RuntimeException e) {
                        staging.wipeAndDelete();
                        throw e;
                    }
                    TarEntry tarEntry = new TarEntry(entry, staging, 0, staging.plaintextSize());
                    if (entry.getLinkName() != null && !entry.getLinkName().isEmpty()) {
                        tarEntry.setLinkName(entry.getLinkName());
                    }
                    archive.addEntry(tarEntry);
                    archive.addStagingTemp(staging);
                }
            }
        }
        return archive;
    }

    /** InputStream.read may return short reads; loop until the buffer is full. */
    private static void readFully(InputStream in, byte[] buf, String entryName) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) {
                throw new IOException("Incomplete read for entry: " + entryName);
            }
            off += n;
        }
    }

    public static boolean isCompound(byte[] data) {
        if (data == null || data.length < 4) return false;
        for (int i = 0; i < 4; i++) {
            if (data[i] != MAGIC[i]) return false;
        }
        return true;
    }

    // For backward compatibility with CompoundCodec
    public static boolean isLegacyCompound(byte[] data) {
        if (data == null || data.length < 4) return false;
        for (int i = 0; i < 4; i++) {
            if (data[i] != MAGIC[i]) return false;
        }
        if (data.length < 5) return false;
        int version = data[4] & 0xFF;
        return version == 1;
    }
}