package io.github.epi155.pgp.model;

import io.github.epi155.pgp.service.SecureTempFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CompoundMessage {

    public static class Attachment {
        private final String filename;
        private final SecureTempFile tempFile;
        private final long offset;
        private final long length;
        private byte[] cachedContent;
        private final long modificationTime;

        public Attachment(String filename, byte[] content) {
            this(filename, content, 0);
        }

        public Attachment(String filename, byte[] content, long modificationTime) {
            this.filename = filename;
            this.tempFile = null;
            this.offset = 0;
            this.length = content.length;
            this.cachedContent = content;
            this.modificationTime = modificationTime;
        }

        public Attachment(String filename, SecureTempFile tempFile, long offset, long length) {
            this(filename, tempFile, offset, length, 0);
        }

        public Attachment(String filename, SecureTempFile tempFile, long offset, long length, long modificationTime) {
            this.filename = filename;
            this.tempFile = tempFile;
            this.offset = offset;
            this.length = length;
            this.cachedContent = null;
            this.modificationTime = modificationTime;
        }

        public String getFilename() { return filename; }

        public long getModificationTime() { return modificationTime; }

        /** Session-encrypted backing store, or null when content is in-memory. */
        public SecureTempFile getTempFile() { return tempFile; }

        /** Plaintext-space offset of this attachment inside {@link #getTempFile()}. */
        public long getOffset() { return offset; }

        /** Plaintext-space length inside {@link #getTempFile()}, or &lt;0 for whole file. */
        public long getLength() { return length; }

        public byte[] getContent() {
            if (cachedContent == null && tempFile != null) {
                try {
                    long len = length >= 0 ? length : tempFile.plaintextSize() - offset;
                    cachedContent = tempFile.readSlice(offset, len);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to read attachment from temp file", e);
                }
            }
            return cachedContent;
        }

        public long getContentLength() {
            if (length >= 0) return length;
            if (tempFile != null) return tempFile.plaintextSize();
            if (cachedContent != null) return cachedContent.length;
            return 0;
        }

        public void saveTo(Path target) throws IOException {
            if (cachedContent != null) {
                Files.write(target, cachedContent);
            } else if (tempFile != null) {
                tempFile.copySliceTo(target, offset, length);
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
