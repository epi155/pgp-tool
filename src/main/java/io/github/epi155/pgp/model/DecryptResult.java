package io.github.epi155.pgp.model;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class DecryptResult {

    public static class EncryptionLayer {
        public enum Type { PUBLIC_KEY, PASSWORD }

        private final Type type;
        private final int encryptionAlgorithm;
        private final int publicKeyAlgorithm;
        private final String curve;
        private final Long recipientKeyId;
        private final List<Long> allRecipientKeyIds;
        private final String recipientUserId;

        public EncryptionLayer(Type type, int encryptionAlgorithm, int publicKeyAlgorithm,
                               Long recipientKeyId, List<Long> allRecipientKeyIds,
                               String recipientUserId) {
            this(type, encryptionAlgorithm, publicKeyAlgorithm, null,
                    recipientKeyId, allRecipientKeyIds, recipientUserId);
        }

        public EncryptionLayer(Type type, int encryptionAlgorithm, int publicKeyAlgorithm,
                               String curve, Long recipientKeyId, List<Long> allRecipientKeyIds,
                               String recipientUserId) {
            this.type = type;
            this.encryptionAlgorithm = encryptionAlgorithm;
            this.publicKeyAlgorithm = publicKeyAlgorithm;
            this.curve = curve;
            this.recipientKeyId = recipientKeyId;
            this.allRecipientKeyIds = allRecipientKeyIds;
            this.recipientUserId = recipientUserId;
        }

        public Type getType() { return type; }
        public int getEncryptionAlgorithm() { return encryptionAlgorithm; }
        public int getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
        public String getCurve() { return curve; }
        public Long getRecipientKeyId() { return recipientKeyId; }
        public List<Long> getAllRecipientKeyIds() { return allRecipientKeyIds; }
        public String getRecipientUserId() { return recipientUserId; }
    }

    public enum VerificationStatus {
        NOT_SIGNED,
        SIGNED_VERIFIED,
        SIGNED_KEY_NOT_FOUND,
        SIGNED_INVALID
    }

    public static class SignerInfo {
        private final long keyId;
        private final VerificationStatus status;
        private final String userId;
        private final int hashAlgorithm;
        private final int publicKeyAlgorithm;
        private final String curve;
        private final Date signatureTime;

        public SignerInfo(long keyId, VerificationStatus status, String userId,
                          int hashAlgorithm, int publicKeyAlgorithm, Date signatureTime) {
            this(keyId, status, userId, hashAlgorithm, publicKeyAlgorithm, null, signatureTime);
        }

        public SignerInfo(long keyId, VerificationStatus status, String userId,
                          int hashAlgorithm, int publicKeyAlgorithm, String curve,
                          Date signatureTime) {
            this.keyId = keyId;
            this.status = status;
            this.userId = userId;
            this.hashAlgorithm = hashAlgorithm;
            this.publicKeyAlgorithm = publicKeyAlgorithm;
            this.curve = curve;
            this.signatureTime = signatureTime;
        }

        public long getKeyId() { return keyId; }
        public VerificationStatus getStatus() { return status; }
        public String getUserId() { return userId; }
        public int getHashAlgorithm() { return hashAlgorithm; }
        public int getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
        public String getCurve() { return curve; }
        public Date getSignatureTime() { return signatureTime; }

        public String getHashAlgorithmName() {
            return Metadata.hashName(hashAlgorithm);
        }
    }

    private final String plainText;
    private final byte[] rawContent;
    private final VerificationStatus verificationStatus;
    private final List<SignerInfo> signers;
    private final Metadata metadata;
    private final CompoundMessage compoundMessage;
    private final java.nio.file.Path tempFilePath;

    public DecryptResult(String plainText, byte[] rawContent, VerificationStatus verificationStatus,
                         List<SignerInfo> signers,
                         Metadata metadata, CompoundMessage compoundMessage) {
        this(plainText, rawContent, verificationStatus, signers, metadata, compoundMessage, null);
    }

    public DecryptResult(String plainText, byte[] rawContent, VerificationStatus verificationStatus,
                         List<SignerInfo> signers,
                         Metadata metadata, CompoundMessage compoundMessage, java.nio.file.Path tempFilePath) {
        this.plainText = plainText;
        this.rawContent = rawContent;
        this.verificationStatus = verificationStatus;
        this.signers = signers != null ? signers : List.of();
        this.metadata = metadata;
        this.compoundMessage = compoundMessage;
        this.tempFilePath = tempFilePath;
    }

    public String getPlainText() { return plainText; }
    public byte[] getRawContent() { return rawContent != null ? rawContent : readTempContent(); }
    public java.nio.file.Path getTempFilePath() { return tempFilePath; }
    public VerificationStatus getVerificationStatus() { return verificationStatus; }
    public Long getSignerKeyId() {
        return signers.isEmpty() ? null : signers.get(0).getKeyId();
    }
    public List<SignerInfo> getSigners() { return signers; }
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
        if (signers.isEmpty()) {
            return "\u2013 Unsigned message";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < signers.size(); i++) {
            SignerInfo s = signers.get(i);
            if (i > 0) sb.append('\n');
            switch (s.getStatus()) {
                case SIGNED_VERIFIED:
                    sb.append(String.format("\u2713 Valid signature from 0x%08X", s.getKeyId()));
                    break;
                case SIGNED_KEY_NOT_FOUND:
                    sb.append(String.format("\u26A0 Signed message but key 0x%08X not found", s.getKeyId()));
                    break;
                case SIGNED_INVALID:
                    sb.append(String.format("\u26A0 Invalid signature (0x%08X)", s.getKeyId()));
                    break;
                default:
                    break;
            }
        }
        return sb.toString();
    }

    public String getMetadataText() {
        return metadata != null ? metadata.format() : "";
    }

    public String getEncryptionMetadataText() {
        return metadata != null ? metadata.formatEncryption() : "";
    }

    public String getVerificationDetail() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><body style=\"font-family:SansSerif;font-size:8px\">");
        if (signers.isEmpty()) {
            sb.append("<span style=\"color:gray\">\u2013 Unsigned message</span>");
        } else {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            for (int i = 0; i < signers.size(); i++) {
                SignerInfo s = signers.get(i);
                if (i > 0) sb.append("<br><br>");
                switch (s.getStatus()) {
                    case SIGNED_VERIFIED:
                        sb.append(String.format(
                                "<span style=\"color:green;font-weight:bold\">\u2713 Valid signature from 0x%08X</span>",
                                s.getKeyId()));
                        break;
                    case SIGNED_KEY_NOT_FOUND:
                        sb.append(String.format(
                                "<span style=\"color:#CC8800;font-weight:bold\">\u26A0 Signed message but key 0x%08X not found</span>",
                                s.getKeyId()));
                        break;
                    case SIGNED_INVALID:
                        sb.append(String.format(
                                "<span style=\"color:red;font-weight:bold\">\u26A0 Invalid signature (0x%08X)</span>",
                                s.getKeyId()));
                        break;
                    default:
                        break;
                }
                if (s.getHashAlgorithm() != 0) {
                    sb.append("<br><span style=\"font-weight:bold\">Hash:</span> ");
                    if (s.getPublicKeyAlgorithm() != 0) {
                        sb.append(Metadata.pubKeyAlgName(s.getPublicKeyAlgorithm()));
                        if (s.getCurve() != null) {
                            sb.append(" (").append(s.getCurve()).append(")");
                        }
                        sb.append('/');
                    }
                    sb.append(s.getHashAlgorithmName());
                }
                if (s.getSignatureTime() != null) {
                    if (s.getHashAlgorithm() != 0) {
                        sb.append(" \u00A0 ");
                    } else {
                        sb.append("<br>");
                    }
                    sb.append("<span style=\"font-weight:bold\">Signature Date:</span> ").append(sdf.format(s.getSignatureTime()));
                }
                if (s.getUserId() != null) {
                    sb.append("<br><span style=\"font-weight:bold\">Signer:</span> ").append(escapeHtml(s.getUserId()));
                }
            }
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    public static class Metadata {
        private final Long recipientKeyId;
        private final List<Long> allRecipientKeyIds;
        private final Integer encryptionAlgorithm;
        private final Integer publicKeyAlgorithm;
        private final Integer compressionAlgorithm;
        private final Character literalFormat;
        private final String fileName;
        private final Date modificationTime;
        private final Long signerKeyId;
        private final Integer hashAlgorithm;
        private final Integer signerPublicKeyAlgorithm;
        private final String signerCurve;
        private final Date signatureCreationTime;
        private final String signerUserId;
        private final String recipientUserId;
        private final List<EncryptionLayer> encryptionLayers;

        private Metadata(Builder b) {
            this.recipientKeyId = b.recipientKeyId;
            this.allRecipientKeyIds = b.allRecipientKeyIds;
            this.encryptionAlgorithm = b.encryptionAlgorithm;
            this.publicKeyAlgorithm = b.publicKeyAlgorithm;
            this.compressionAlgorithm = b.compressionAlgorithm;
            this.literalFormat = b.literalFormat;
            this.fileName = b.fileName;
            this.modificationTime = b.modificationTime;
            this.signerKeyId = b.signerKeyId;
            this.hashAlgorithm = b.hashAlgorithm;
            this.signerPublicKeyAlgorithm = b.signerPublicKeyAlgorithm;
            this.signerCurve = b.signerCurve;
            this.signatureCreationTime = b.signatureCreationTime;
            this.signerUserId = b.signerUserId;
            this.recipientUserId = b.recipientUserId;
            this.encryptionLayers = b.encryptionLayers;
        }

        public Long getRecipientKeyId() { return recipientKeyId; }
        public List<Long> getAllRecipientKeyIds() { return allRecipientKeyIds; }
        public Long getSignerKeyId() { return signerKeyId; }
        public String getRecipientUserId() { return recipientUserId; }
        public List<EncryptionLayer> getEncryptionLayers() { return encryptionLayers; }
        public String getOriginalFileName() {
            if (fileName != null && !fileName.isEmpty() && !"_CONSOLE".equals(fileName))
                return fileName;
            return null;
        }

        public String format() {
            StringBuilder sb = new StringBuilder();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            if (encryptionLayers != null && !encryptionLayers.isEmpty()) {
                for (int i = 0; i < encryptionLayers.size(); i++) {
                    EncryptionLayer layer = encryptionLayers.get(i);
                    sb.append("Layer ").append(i + 1).append(": ");
                    if (layer.getType() == EncryptionLayer.Type.PASSWORD) {
                        sb.append("Password-based/").append(algName(layer.getEncryptionAlgorithm()));
                    } else {
                        if (layer.getPublicKeyAlgorithm() != 0) {
                            sb.append(pubKeyAlgName(layer.getPublicKeyAlgorithm()));
                            if (layer.getCurve() != null) {
                                sb.append(" (").append(layer.getCurve()).append(")");
                            }
                            sb.append('/');
                        }
                        sb.append(algName(layer.getEncryptionAlgorithm()));
                        if (layer.getAllRecipientKeyIds() != null && !layer.getAllRecipientKeyIds().isEmpty()) {
                            sb.append(" (keys:");
                            for (long id : layer.getAllRecipientKeyIds()) {
                                sb.append(" 0x").append(String.format("%08X", id));
                            }
                            sb.append(')');
                        }
                    }
                    sb.append('\n');
                }
            } else {
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
                if (encryptionAlgorithm != null) {
                    sb.append("Encryption: ");
                    if (publicKeyAlgorithm != null && publicKeyAlgorithm != 0) {
                        sb.append(pubKeyAlgName(publicKeyAlgorithm)).append('/');
                    }
                    sb.append(algName(encryptionAlgorithm)).append('\n');
                }
            }

            if (compressionAlgorithm != null) {
                sb.append("Compression: ").append(compName(compressionAlgorithm)).append('\n');
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
            if (signerPublicKeyAlgorithm != null && signerPublicKeyAlgorithm != 0) {
                sb.append("Signer Key: ").append(pubKeyAlgName(signerPublicKeyAlgorithm));
                if (signerCurve != null) {
                    sb.append(" (").append(signerCurve).append(")");
                }
                sb.append('\n');
            }
            if (hashAlgorithm != null)
                sb.append("Hash: ").append(hashName(hashAlgorithm)).append('\n');
            if (signatureCreationTime != null)
                sb.append("Signature Date: ").append(sdf.format(signatureCreationTime)).append('\n');
            if (signerUserId != null)
                sb.append("Signer: ").append(signerUserId).append('\n');

            return sb.toString().stripTrailing();
        }

        public String formatEncryption() {
            StringBuilder sb = new StringBuilder();
            sb.append("<html><body style=\"font-family:SansSerif;font-size:8px\">");
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

            if (encryptionLayers != null && !encryptionLayers.isEmpty()) {
                for (int i = 0; i < encryptionLayers.size(); i++) {
                    EncryptionLayer layer = encryptionLayers.get(i);
                    sb.append("<b>Layer ").append(i + 1).append(":</b> ");
                    if (layer.getType() == EncryptionLayer.Type.PASSWORD) {
                        sb.append("Password-based/").append(algName(layer.getEncryptionAlgorithm()));
                    } else {
                        if (layer.getPublicKeyAlgorithm() != 0) {
                            sb.append(pubKeyAlgName(layer.getPublicKeyAlgorithm()));
                            if (layer.getCurve() != null) {
                                sb.append(" (").append(layer.getCurve()).append(")");
                            }
                            sb.append('/');
                        }
                        sb.append(algName(layer.getEncryptionAlgorithm()));
                        if (layer.getRecipientUserId() != null) {
                            sb.append(" for ").append(escapeHtml(layer.getRecipientUserId()));
                        }
                        if (layer.getAllRecipientKeyIds() != null && !layer.getAllRecipientKeyIds().isEmpty()) {
                            sb.append(" (keys:");
                            for (long id : layer.getAllRecipientKeyIds()) {
                                sb.append(' ');
                                if (layer.getRecipientKeyId() != null && id == layer.getRecipientKeyId()) {
                                    sb.append("<b>0x").append(String.format("%08X", id)).append("</b>");
                                } else {
                                    sb.append("0x").append(String.format("%08X", id));
                                }
                            }
                            sb.append(')');
                        }
                    }
                    sb.append("<br>");
                }
            } else {
                if (allRecipientKeyIds != null && !allRecipientKeyIds.isEmpty()) {
                    sb.append("<b>Recipient Key IDs:</b>");
                    for (long id : allRecipientKeyIds) {
                        sb.append(' ');
                        if (recipientKeyId != null && id == recipientKeyId) {
                            sb.append("<b>0x").append(String.format("%08X", id)).append("</b>");
                        } else {
                            sb.append("0x").append(String.format("%08X", id));
                        }
                    }
                    sb.append("<br>");
                }
                if (recipientUserId != null) {
                    sb.append("<b>User:</b> ").append(recipientUserId).append("<br>");
                }
                if (encryptionAlgorithm != null) {
                    sb.append("<b>Encryption:</b> ");
                    if (publicKeyAlgorithm != null && publicKeyAlgorithm != 0) {
                        sb.append(pubKeyAlgName(publicKeyAlgorithm)).append('/');
                    }
                    sb.append(algName(encryptionAlgorithm)).append("<br>");
                }
            }

            {
                StringBuilder line = new StringBuilder();
                if (compressionAlgorithm != null) {
                    line.append("<b>Compression:</b> ").append(compName(compressionAlgorithm));
                }
                if (modificationTime != null) {
                    if (line.length() > 0) line.append(" \u00A0 ");
                    line.append("<b>Timestamp:</b> ").append(sdf.format(modificationTime));
                }
                if (line.length() > 0) {
                    sb.append(line).append("<br>");
                }
            }
            if (literalFormat != null) {
                sb.append("<b>Format:</b> ").append(formatName(literalFormat));
                if (fileName != null && !fileName.isEmpty() && !"_CONSOLE".equals(fileName))
                    sb.append(" (").append(fileName).append(')');
                sb.append("<br>");
            }
            sb.append("</body></html>");
            return sb.toString();
        }

        public String getHashAlgorithmName() {
            return hashAlgorithm != null ? hashName(hashAlgorithm) : "";
        }

        public static class Builder {
            private Long recipientKeyId;
            private List<Long> allRecipientKeyIds;
            private Integer encryptionAlgorithm;
            private Integer publicKeyAlgorithm;
            private Integer compressionAlgorithm;
            private Character literalFormat;
            private String fileName;
            private Date modificationTime;
            private Long signerKeyId;
            private Integer hashAlgorithm;
            private Integer signerPublicKeyAlgorithm;
            private String signerCurve;
            private Date signatureCreationTime;
            private String signerUserId;
            private String recipientUserId;
            private List<EncryptionLayer> encryptionLayers;

            public Builder recipientKeyId(long v) { this.recipientKeyId = v; return this; }
            public Builder allRecipientKeyIds(List<Long> v) { this.allRecipientKeyIds = v; return this; }
            public Builder encryptionAlgorithm(int v) { this.encryptionAlgorithm = v; return this; }
            public Builder publicKeyAlgorithm(int v) { this.publicKeyAlgorithm = v; return this; }
            public Builder compressionAlgorithm(int v) { this.compressionAlgorithm = v; return this; }
            public Builder literalFormat(char v) { this.literalFormat = v; return this; }
            public Builder fileName(String v) { this.fileName = v; return this; }
            public Builder modificationTime(Date v) { this.modificationTime = v; return this; }
            public Builder signerKeyId(long v) { this.signerKeyId = v; return this; }
            public Builder hashAlgorithm(int v) { this.hashAlgorithm = v; return this; }
            public Builder signerPublicKeyAlgorithm(int v) { this.signerPublicKeyAlgorithm = v; return this; }
            public Builder signerCurve(String v) { this.signerCurve = v; return this; }
            public Builder signatureCreationTime(Date v) { this.signatureCreationTime = v; return this; }
            public Builder signerUserId(String v) { this.signerUserId = v; return this; }
            public Builder recipientUserId(String v) { this.recipientUserId = v; return this; }
            public Builder encryptionLayers(List<EncryptionLayer> v) { this.encryptionLayers = v; return this; }
            public Integer getEncryptionAlgorithm() { return encryptionAlgorithm; }
            public Metadata build() { return new Metadata(this); }
        }

        static String hashName(int algo) {
            switch (algo) {
                case 1: return "MD5";
                case 2: return "SHA-1";
                case 3: return "RIPEMD160";
                case 8: return "SHA-256";
                case 9: return "SHA-384";
                case 10: return "SHA-512";
                case 11: return "SHA-224";
                case 12: return "SHA3-256";
                case 13: return "SHA3-384";
                case 14: return "SHA3-512";
                case 15: return "SHA3-224";
                case 27: return "SHAKE256";
                default: return "Hash#" + algo;
            }
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
                case 11: return "Camellia-128";
                case 12: return "Camellia-192";
                case 13: return "Camellia-256";
                case 100: return "Serpent-128";
                case 101: return "Serpent-192";
                case 102: return "Serpent-256";
                case 103: return "ChaCha20-Poly1305";
                case 104: return "ASCON";
                default: return "Algo#" + algo;
            }
        }

        private static String pubKeyAlgName(int algo) {
            switch (algo) {
                case PublicKeyAlgorithmTags.RSA_GENERAL:
                case PublicKeyAlgorithmTags.RSA_ENCRYPT:
                case PublicKeyAlgorithmTags.RSA_SIGN:
                    return "RSA";
                case PublicKeyAlgorithmTags.DSA:
                    return "DSA";
                case PublicKeyAlgorithmTags.ECDSA:
                    return "ECDSA";
                case PublicKeyAlgorithmTags.ECDH:
                    return "ECDH";
                case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT:
                case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
                    return "ElGamal";
                case PublicKeyAlgorithmTags.DIFFIE_HELLMAN:
                    return "DH";
                case PublicKeyAlgorithmTags.EDDSA:
                    return "EdDSA";
                case PublicKeyAlgorithmTags.Ed25519:
                    return "Ed25519";
                case PublicKeyAlgorithmTags.Ed448:
                    return "Ed448";
                case PublicKeyAlgorithmTags.X25519:
                    return "X25519";
                case PublicKeyAlgorithmTags.X448:
                    return "X448";
                default:
                    return "Algo#" + algo;
            }
        }

        private static String compName(int algo) {
            switch (algo) {
                case 0: return "Uncompressed";
                case 1: return "ZIP";
                case 2: return "ZLIB";
                case 3: return "BZIP2";
                case 128: return "XZ";
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
    }
}
