package com.example.pgp.model;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CompoundMessage {

    public static class Attachment {
        private final String filename;
        private final Path tempFile;
        private final long offset;
        private final long length;
        private byte[] cachedContent;

        public Attachment(String filename, byte[] content) {
            this.filename = filename;
            this.tempFile = null;
            this.offset = 0;
            this.length = content.length;
            this.cachedContent = content;
        }

        public Attachment(String filename, Path tempFile, long offset, long length) {
            this.filename = filename;
            this.tempFile = tempFile;
            this.offset = offset;
            this.length = length;
            this.cachedContent = null;
        }

        public String getFilename() { return filename; }

        public byte[] getContent() {
            if (cachedContent == null && tempFile != null) {
                try {
                    cachedContent = Files.readAllBytes(tempFile);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to read attachment from temp file", e);
                }
            }
            return cachedContent;
        }

        public long getContentLength() {
            if (length >= 0) return length;
            if (tempFile != null) {
                try { return java.nio.file.Files.size(tempFile); } catch (IOException ignored) {}
            }
            if (cachedContent != null) return cachedContent.length;
            return 0;
        }

        public void saveTo(Path target) throws IOException {
            if (cachedContent != null) {
                Files.write(target, cachedContent);
            } else if (tempFile != null) {
                long fileSize = Files.size(tempFile);
                if (offset == 0 && (length < 0 || length == fileSize)) {
                    Files.copy(tempFile, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                } else {
                    try (InputStream in = Files.newInputStream(tempFile, StandardOpenOption.READ);
                         OutputStream out = Files.newOutputStream(target)) {
                        in.skip(offset);
                        long remaining = length >= 0 ? length : fileSize - offset;
                        byte[] buf = new byte[65536];
                        while (remaining > 0) {
                            int chunk = (int) Math.min(buf.length, remaining);
                            int n = in.read(buf, 0, chunk);
                            if (n < 0) break;
                            out.write(buf, 0, n);
                            remaining -= n;
                        }
                    }
                }
            }
        }

        public void dispose() {
            cachedContent = null;
        }
    }

    private final String plainText;
    private final List<Attachment> attachments;

    public CompoundMessage(String plainText, List<Attachment> attachments) {
        this.plainText = plainText;
        this.attachments = attachments != null ? new ArrayList<>(attachments) : new ArrayList<>();
    }

    public String getPlainText() { return plainText; }
    public List<Attachment> getAttachments() { return Collections.unmodifiableList(attachments); }
    public boolean hasAttachments() { return !attachments.isEmpty(); }
}
