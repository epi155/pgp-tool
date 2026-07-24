package com.example.pgp.model;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class DecryptResult {

    public enum VerificationStatus {
        NOT_SIGNED,
        SIGNED_VERIFIED,
        SIGNED_KEY_NOT_FOUND,
        SIGNED_INVALID
    }

    private final String plainText;
    private final byte[] rawContent;
    private final VerificationStatus verificationStatus;
    private final Long signerKeyId;
    private final Metadata metadata;
    private final CompoundMessage compoundMessage;
    private final java.nio.file.Path tempFilePath;

    public DecryptResult(String plainText, VerificationStatus verificationStatus, Long signerKeyId) {
        this(plainText, verificationStatus, signerKeyId, null, null);
    }

    public DecryptResult(String plainText, VerificationStatus verificationStatus, Long signerKeyId, Metadata metadata) {
        this(plainText, verificationStatus, signerKeyId, metadata, null);
    }

    public DecryptResult(String plainText, VerificationStatus verificationStatus, Long signerKeyId,
                         Metadata metadata, CompoundMessage compoundMessage) {
        this(plainText, null, verificationStatus, signerKeyId, metadata, compoundMessage);
    }

    public DecryptResult(String plainText, byte[] rawContent, VerificationStatus verificationStatus, Long signerKeyId,
                         Metadata metadata, CompoundMessage compoundMessage) {
        this(plainText, rawContent, verificationStatus, signerKeyId, metadata, compoundMessage, null);
    }

    public DecryptResult(String plainText, byte[] rawContent, VerificationStatus verificationStatus, Long signerKeyId,
                         Metadata metadata, CompoundMessage compoundMessage, java.nio.file.Path tempFilePath) {
        this.plainText = plainText;
        this.rawContent = rawContent;
        this.verificationStatus = verificationStatus;
        this.signerKeyId = signerKeyId;
        this.metadata = metadata;
        this.compoundMessage = compoundMessage;
        this.tempFilePath = tempFilePath;
    }

    public String getPlainText() { return plainText; }
    public byte[] getRawContent() { return rawContent != null ? rawContent : readTempContent(); }
    public java.nio.file.Path getTempFilePath() { return tempFilePath; }
    public VerificationStatus getVerificationStatus() { return verificationStatus; }
    public Long getSignerKeyId() { return signerKeyId; }
    public Metadata getMetadata() { return metadata; }
    public CompoundMessage getCompoundMessage() { return compoundMessage; }

    private byte[] readTempContent() {
        if (tempFilePath != null) {
            try {
                return java.nio.file.Files.readAllBytes(tempFilePath);
            } catch (java.io.IOException ignored) {}
        }
        return null;
    }

    public String getVerificationMessage() {
        switch (verificationStatus) {
            case NOT_SIGNED:
                return "\u2013 Messaggio non firmato";
            case SIGNED_VERIFIED:
                return String.format("\u2713 Firma valida da 0x%08X", signerKeyId);
            case SIGNED_KEY_NOT_FOUND:
                return String.format("\u26A0 Messaggio firmato ma chiave 0x%08X non trovata", signerKeyId);
            case SIGNED_INVALID:
                return String.format("\u26A0 Firma NON valida (0x%08X)", signerKeyId);
            default:
                return "";
        }
    }

    public String getMetadataText() {
        return metadata != null ? metadata.format() : "";
    }

    public String getEncryptionMetadataText() {
        return metadata != null ? metadata.formatEncryption() : "";
    }

    public String getVerificationDetail() {
        String msg = getVerificationMessage();
        if (metadata == null) return msg;
        StringBuilder sb = new StringBuilder(msg);
        if (metadata.hashAlgorithm != null) {
            sb.append(" (Hash: ").append(metadata.getHashAlgorithmName()).append(')');
        }
        sb.append('\n');
        if (metadata.signatureCreationTime != null) {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            sb.append("Signature Date: ").append(sdf.format(metadata.signatureCreationTime)).append('\n');
        }
        if (metadata.signerUserId != null) {
            sb.append("Signer: ").append(metadata.signerUserId).append('\n');
        }
        return sb.toString().stripTrailing();
    }

    public static class Metadata {
        private final Long recipientKeyId;
        private final List<Long> allRecipientKeyIds;
        private final Integer encryptionAlgorithm;
        private final Integer compressionAlgorithm;
        private final Character literalFormat;
        private final String fileName;
        private final Date modificationTime;
        private final Long signerKeyId;
        private final Integer hashAlgorithm;
        private final Date signatureCreationTime;
        private final String signerUserId;
        private final String recipientUserId;

        private Metadata(Builder b) {
            this.recipientKeyId = b.recipientKeyId;
            this.allRecipientKeyIds = b.allRecipientKeyIds;
            this.encryptionAlgorithm = b.encryptionAlgorithm;
            this.compressionAlgorithm = b.compressionAlgorithm;
            this.literalFormat = b.literalFormat;
            this.fileName = b.fileName;
            this.modificationTime = b.modificationTime;
            this.signerKeyId = b.signerKeyId;
            this.hashAlgorithm = b.hashAlgorithm;
            this.signatureCreationTime = b.signatureCreationTime;
            this.signerUserId = b.signerUserId;
            this.recipientUserId = b.recipientUserId;
        }

        public Long getRecipientKeyId() { return recipientKeyId; }
        public List<Long> getAllRecipientKeyIds() { return allRecipientKeyIds; }
        public Long getSignerKeyId() { return signerKeyId; }
        public String getRecipientUserId() { return recipientUserId; }
        public String getOriginalFileName() {
            if (fileName != null && !fileName.isEmpty() && !"_CONSOLE".equals(fileName))
                return fileName;
            return null;
        }

        public String format() {
            StringBuilder sb = new StringBuilder();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            if (allRecipientKeyIds != null && !allRecipientKeyIds.isEmpty()) {
                sb.append("Recipient Key IDs:");
                for (long id : allRecipientKeyIds) {
                    sb.append(" 0x").append(String.format("%08X", id));
                    if (recipientKeyId != null && id == recipientKeyId)
                        sb.append('*');
                }
                sb.append('\n');
            }
            if (recipientUserId != null)
                sb.append("User: ").append(recipientUserId).append('\n');
            if (encryptionAlgorithm != null || compressionAlgorithm != null) {
                sb.append("Encryption/Compression: ");
                if (encryptionAlgorithm != null)
                    sb.append(algName(encryptionAlgorithm));
                if (compressionAlgorithm != null)
                    sb.append(" / ").append(compName(compressionAlgorithm));
                sb.append('\n');
            }
            if (literalFormat != null) {
                sb.append("Format: ").append(formatName(literalFormat));
                if (fileName != null && !fileName.isEmpty() && !"_CONSOLE".equals(fileName))
                    sb.append(" (").append(fileName).append(')');
                sb.append('\n');
            }
            if (modificationTime != null)
                sb.append("Timestamp: ").append(sdf.format(modificationTime)).append('\n');
            if (signerKeyId != null)
                sb.append("Signer Key ID: 0x").append(String.format("%08X", signerKeyId)).append('\n');
            if (hashAlgorithm != null)
                sb.append("Hash: ").append(hashName(hashAlgorithm)).append('\n');
            if (signatureCreationTime != null)
                sb.append("Signature Date: ").append(sdf.format(signatureCreationTime)).append('\n');
            if (signerUserId != null)
                sb.append("Signer: ").append(signerUserId).append('\n');

            return sb.toString().stripTrailing();
        }

        public String formatEncryption() {
            if (allRecipientKeyIds == null && encryptionAlgorithm == null
                    && compressionAlgorithm == null && literalFormat == null
                    && modificationTime == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            if (allRecipientKeyIds != null && !allRecipientKeyIds.isEmpty()) {
                sb.append("Recipient Key IDs:");
                for (long id : allRecipientKeyIds) {
                    sb.append(" 0x").append(String.format("%08X", id));
                    if (recipientKeyId != null && id == recipientKeyId)
                        sb.append('*');
                }
                sb.append('\n');
            }
            if (recipientUserId != null)
                sb.append("User: ").append(recipientUserId).append('\n');
            if (encryptionAlgorithm != null || compressionAlgorithm != null) {
                sb.append("Encryption/Compression: ");
                if (encryptionAlgorithm != null)
                    sb.append(algName(encryptionAlgorithm));
                if (compressionAlgorithm != null)
                    sb.append(" / ").append(compName(compressionAlgorithm));
                sb.append('\n');
            }
            if (literalFormat != null) {
                sb.append("Format: ").append(formatName(literalFormat));
                if (fileName != null && !fileName.isEmpty() && !"_CONSOLE".equals(fileName))
                    sb.append(" (").append(fileName).append(')');
                sb.append('\n');
            }
            if (modificationTime != null)
                sb.append("Timestamp: ").append(sdf.format(modificationTime)).append('\n');
            return sb.toString().stripTrailing();
        }

        public String getHashAlgorithmName() {
            return hashAlgorithm != null ? hashName(hashAlgorithm) : "";
        }

        public String formatSignature() {
            if (signerKeyId == null && hashAlgorithm == null
                    && signatureCreationTime == null && signerUserId == null) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            if (signerKeyId != null)
                sb.append("Signer Key ID: 0x").append(String.format("%08X", signerKeyId)).append('\n');
            if (hashAlgorithm != null)
                sb.append("Hash: ").append(hashName(hashAlgorithm)).append('\n');
            if (signatureCreationTime != null)
                sb.append("Signature Date: ").append(sdf.format(signatureCreationTime)).append('\n');
            if (signerUserId != null)
                sb.append("Signer: ").append(signerUserId).append('\n');
            return sb.toString().stripTrailing();
        }

        public static class Builder {
            private Long recipientKeyId;
            private List<Long> allRecipientKeyIds;
            private Integer encryptionAlgorithm;
            private Integer compressionAlgorithm;
            private Character literalFormat;
            private String fileName;
            private Date modificationTime;
            private Long signerKeyId;
            private Integer hashAlgorithm;
            private Date signatureCreationTime;
            private String signerUserId;
            private String recipientUserId;

            public Builder recipientKeyId(long v) { this.recipientKeyId = v; return this; }
            public Builder allRecipientKeyIds(List<Long> v) { this.allRecipientKeyIds = v; return this; }
            public Builder encryptionAlgorithm(int v) { this.encryptionAlgorithm = v; return this; }
            public Builder compressionAlgorithm(int v) { this.compressionAlgorithm = v; return this; }
            public Builder literalFormat(char v) { this.literalFormat = v; return this; }
            public Builder fileName(String v) { this.fileName = v; return this; }
            public Builder modificationTime(Date v) { this.modificationTime = v; return this; }
            public Builder signerKeyId(long v) { this.signerKeyId = v; return this; }
            public Builder hashAlgorithm(int v) { this.hashAlgorithm = v; return this; }
            public Builder signatureCreationTime(Date v) { this.signatureCreationTime = v; return this; }
            public Builder signerUserId(String v) { this.signerUserId = v; return this; }
            public Builder recipientUserId(String v) { this.recipientUserId = v; return this; }
            public Metadata build() { return new Metadata(this); }
        }

        private static String algName(int algo) {
            switch (algo) {
                case 1: return "IDEA";
                case 2: return "Triple-DES";
                case 3: return "CAST5";
                case 4: return "Blowfish";
                case 5: return "SAFER-SK128";
                case 6: return "DES";
                case 7: return "AES-128";
                case 8: return "AES-192";
                case 9: return "AES-256";
                case 10: return "Twofish";
                default: return "Algo#" + algo;
            }
        }

        private static String compName(int algo) {
            switch (algo) {
                case 0: return "Uncompressed";
                case 1: return "ZIP";
                case 2: return "ZLIB";
                case 3: return "BZIP2";
                default: return "Algo#" + algo;
            }
        }

        private static String formatName(char fmt) {
            switch (fmt) {
                case 'b': return "Binary";
                case 't': return "Text";
                case 'u': return "UTF8";
                case 'l': return "Local";
                default: return "'" + fmt + "'";
            }
        }

        private static String hashName(int algo) {
            switch (algo) {
                case 1: return "MD5";
                case 2: return "SHA-1";
                case 3: return "RIPEMD160";
                case 8: return "SHA-256";
                case 9: return "SHA-384";
                case 10: return "SHA-512";
                case 11: return "SHA-224";
                default: return "Hash#" + algo;
            }
        }
    }
}
