package io.github.epi155.pgp.model;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;

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
            Path tempFile = Files.createTempFile("tar-", ".tar");
            try {
                long tarSize;
                try (OutputStream tarOut = Files.newOutputStream(tempFile)) {
                    archive.writeTo(tarOut);
                }
                tarSize = Files.size(tempFile);

                byte[] nameBytes = archive.getTarFileName().getBytes(StandardCharsets.UTF_8);
                dataOut.writeByte(1);
                dataOut.writeInt(nameBytes.length);
                dataOut.write(nameBytes);
                dataOut.writeLong(tarSize);
                byte[] buf = new byte[8192];
                try (InputStream tarIn = Files.newInputStream(tempFile)) {
                    int n;
                    while ((n = tarIn.read(buf)) >= 0) {
                        dataOut.write(buf, 0, n);
                    }
                }
            } finally {
                Files.deleteIfExists(tempFile);
            }
        }

        dataOut.flush();
    }

    public static TarArchive decode(InputStream in, int totalSize, Path tempFile) throws IOException {
        DataInputStream dataIn = new DataInputStream(in);

        byte[] magic = new byte[4];
        dataIn.readFully(magic);
        for (int i = 0; i < 4; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IOException("Not a PGPC compound message");
            }
        }

        int version = dataIn.readUnsignedByte();
        if (version != 1 && version != 2 && version != VERSION) {
            throw new IOException("Unsupported PGPC version: " + version);
        }

        // For v1/v2, delegate to CompoundCodec
        if (version == 1 || version == 2) {
            // Need to re-read from beginning - create a new stream with the data we already read
            // For simplicity, we'll handle this by reading the rest and prepending what we read
            // Actually, CompoundCodec expects to read from the start, so we need a different approach
            // Let's read all remaining data and prepend the header
            ByteArrayOutputStream fullBuf = new ByteArrayOutputStream();
            fullBuf.write(magic);
            fullBuf.write(version);
            byte[] rest = dataIn.readAllBytes();
            fullBuf.write(rest);
            CompoundMessage compound = CompoundCodec.decode(new ByteArrayInputStream(fullBuf.toByteArray()), totalSize, tempFile);
            // Convert CompoundMessage to TarArchive
            TarArchive archive = new TarArchive();
            archive.setPlainText(compound.getPlainText());
            for (CompoundMessage.Attachment att : compound.getAttachments()) {
                TarEntry entry = new TarEntry(att.getFilename(), att.getContent(), att.getModificationTime());
                archive.addEntry(entry);
            }
            return archive;
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
                    // Write tar content to temp file for streaming decode
                    Path tarTempFile = Files.createTempFile("tar-", ".tar");
                    try (OutputStream tarOut = Files.newOutputStream(tarTempFile)) {
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

                    // Decode tar from temp file
                    try (InputStream tarIn = Files.newInputStream(tarTempFile)) {
                        archive = decodeTar(tarIn);
                    } finally {
                        Files.deleteIfExists(tarTempFile);
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

    private static TarArchive decodeTar(InputStream in) throws IOException {
        TarArchive archive = new TarArchive();
        try (TarArchiveInputStream tarIn = new TarArchiveInputStream(in)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextTarEntry()) != null) {
                if (entry.isDirectory()) {
                    continue;
                }
                long size = entry.getSize();
                if (entry.isSymbolicLink()) {
                    byte[] content = new byte[(int) size];
                    tarIn.read(content);
                    String linkTarget = new String(content, StandardCharsets.UTF_8);
                    TarEntry tarEntry = new TarEntry(entry);
                    tarEntry.setLinkName(linkTarget);
                    tarEntry.setSize(linkTarget.length());
                    archive.addEntry(tarEntry);
                } else if (size <= 50_000_000) {
                    byte[] content = new byte[(int) size];
                    int read = tarIn.read(content);
                    if (read != size) {
                        throw new IOException("Incomplete read for entry: " + entry.getName());
                    }
                    TarEntry tarEntry = new TarEntry(entry.getName(), content, entry.getModTime().getTime());
                    tarEntry.setMode(entry.getMode());
                    tarEntry.setUserName(entry.getUserName());
                    tarEntry.setGroupName(entry.getGroupName());
                    tarEntry.setUserId(entry.getUserId());
                    tarEntry.setGroupId(entry.getGroupId());
                    if (entry.getLinkName() != null && !entry.getLinkName().isEmpty()) {
                        tarEntry.setLinkName(entry.getLinkName());
                    }
                    archive.addEntry(tarEntry);
                } else {
                    TarEntry tarEntry = new TarEntry(entry);
                    if (entry.getLinkName() != null && !entry.getLinkName().isEmpty()) {
                        tarEntry.setLinkName(entry.getLinkName());
                    }
                    archive.addEntry(tarEntry);
                }
            }
        }
        return archive;
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
        return version == 1 || version == 2;
    }
}