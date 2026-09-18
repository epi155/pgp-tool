package io.github.epi155.pgp.model;

import io.github.epi155.pgp.service.SecureTempFile;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class CompoundCodec {

    private static final byte[] MAGIC = {'P', 'G', 'P', 'C'};
    private static final byte TYPE_TEXT = 0;
    private static final byte TYPE_BINARY = 1;

    public static CompoundMessage decode(InputStream in, int totalSize, SecureTempFile tempFile) throws IOException {
        DataInputStream dataIn = new DataInputStream(in);

        byte[] magic = new byte[4];
        dataIn.readFully(magic);
        for (int i = 0; i < 4; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IOException("Not a PGPC compound message");
            }
        }

        int version = dataIn.readUnsignedByte();
        if (version != 1) {
            throw new IOException("Unsupported PGPC version: " + version);
        }

        int numParts = dataIn.readInt();
        String plainText = null;
        List<CompoundMessage.Attachment> attachments = new ArrayList<>();

        long cumulativeOffset = 4 + 1 + 4; // magic + version + numParts

        for (int i = 0; i < numParts; i++) {
            int type = dataIn.readUnsignedByte();
            int filenameLen = dataIn.readInt();
            cumulativeOffset += 1 + 4;
            String filename = "";
            if (filenameLen > 0) {
                byte[] nameBytes = new byte[filenameLen];
                dataIn.readFully(nameBytes);
                cumulativeOffset += filenameLen;
                filename = new String(nameBytes, StandardCharsets.UTF_8);
            }
            long modificationTime = 0;
            long contentLen = dataIn.readLong();
            cumulativeOffset += 8;
            if (contentLen > Integer.MAX_VALUE) {
                throw new IOException("Part too large: " + contentLen);
            }
            int contentLenInt = (int) contentLen;

            if (type == TYPE_TEXT && filenameLen == 0) {
                byte[] content = new byte[contentLenInt];
                dataIn.readFully(content);
                cumulativeOffset += contentLenInt;
                plainText = new String(content, StandardCharsets.UTF_8);
            } else {
                if (tempFile != null) {
                    dataIn.skipBytes(contentLenInt);
                    cumulativeOffset += contentLenInt;
                    attachments.add(new CompoundMessage.Attachment(
                            filename, tempFile, cumulativeOffset - contentLenInt, contentLenInt, modificationTime));
                } else {
                    byte[] content = new byte[contentLenInt];
                    dataIn.readFully(content);
                    cumulativeOffset += contentLenInt;
                    attachments.add(new CompoundMessage.Attachment(filename, content, modificationTime));
                }
            }
        }

        if (plainText == null) plainText = "";
        return new CompoundMessage(plainText, attachments);
    }

    public static boolean isCompound(byte[] data) {
        if (data == null || data.length < 4) return false;
        for (int i = 0; i < 4; i++) {
            if (data[i] != MAGIC[i]) return false;
        }
        return true;
    }

}
