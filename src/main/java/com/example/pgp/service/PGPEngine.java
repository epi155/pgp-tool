package com.example.pgp.service;

import com.example.pgp.model.CompoundCodec;
import com.example.pgp.model.CompoundMessage;
import com.example.pgp.model.DecryptResult;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

public class PGPEngine {

    private static final int CHUNK_SIZE = 65536;

    private final Map<Long, char[]> passphraseCache = new HashMap<>();

    // ─── Encrypt stream (byte[] → OutputStream) ───────────────────

    public void encrypt(byte[] data, String fileName, OutputStream out,
                        List<PGPPublicKey> encKeys, PGPSecretKey signKey, char[] passphrase,
                        int symmetricAlgorithm, int compressionAlgorithm,
                        int hashAlgorithm, boolean armor,
                        ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));
            for (PGPPublicKey key : encKeys) {
                encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC"));
            }
            try (OutputStream encOut = encGen.open(armored, new byte[CHUNK_SIZE])) {
                PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(compressionAlgorithm);
                try (OutputStream zipOut = comData.open(encOut)) {
                    writeSignAndLiteral(zipOut, data, fileName, signKey, passphrase, hashAlgorithm, progress);
                }
            }
        }
    }

    public void encryptPassword(byte[] data, String fileName, OutputStream out,
                                 char[] password, PGPSecretKey signKey, char[] signPassphrase,
                                 int symmetricAlgorithm, int compressionAlgorithm,
                                 int hashAlgorithm, boolean armor,
                                 ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));
            encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password).setProvider("BC"));
            try (OutputStream encOut = encGen.open(armored, new byte[CHUNK_SIZE])) {
                PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(compressionAlgorithm);
                try (OutputStream zipOut = comData.open(encOut)) {
                    writeSignAndLiteral(zipOut, data, fileName, signKey, signPassphrase, hashAlgorithm, progress);
                }
            }
        }
    }

    public void encryptCompress(byte[] data, String fileName, OutputStream out,
                                 PGPSecretKey signKey, char[] signPassphrase,
                                 int compressionAlgorithm,
                                 int hashAlgorithm, boolean armor,
                                 ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(compressionAlgorithm);
            try (OutputStream zipOut = comData.open(armored)) {
                writeSignAndLiteral(zipOut, data, fileName, signKey, signPassphrase, hashAlgorithm, progress);
            }
        }
    }

    // ─── writeSignAndLiteral (byte[]) ─────────────────────────────

    private void writeSignAndLiteral(OutputStream out, byte[] data, String fileName,
                                      PGPSecretKey signKey, char[] signPassphrase,
                                      int hashAlgorithm,
                                      ProgressCallback progress) throws Exception {
        int total = data.length;
        if (signKey != null) {
            PGPPrivateKey signPrivateKey = signKey.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(signPassphrase));
            PGPPublicKey signPubKey = signKey.getPublicKey();
            PGPSignatureGenerator sigGen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(signPubKey.getAlgorithm(), hashAlgorithm)
                            .setProvider("BC"));
            sigGen.init(PGPSignature.BINARY_DOCUMENT, signPrivateKey);
            PGPOnePassSignature ops = sigGen.generateOnePassVersion(false);
            ops.encode(out);
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            try (OutputStream litOut = litGen.open(out, PGPLiteralData.BINARY,
                    fileName, total, new Date())) {
                int offset = 0;
                while (offset < total) {
                    int chunk = Math.min(CHUNK_SIZE, total - offset);
                    sigGen.update(data, offset, chunk);
                    litOut.write(data, offset, chunk);
                    offset += chunk;
                    if (progress != null)
                        progress.onProgress(offset * 100 / total, "Encrypting...");
                }
            }
            sigGen.generate().encode(out);
        } else {
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            try (OutputStream dataOutputStream = litGen.open(out, PGPLiteralData.BINARY,
                    fileName, total, new Date())) {
                int offset = 0;
                while (offset < total) {
                    int chunk = Math.min(CHUNK_SIZE, total - offset);
                    dataOutputStream.write(data, offset, chunk);
                    offset += chunk;
                    if (progress != null)
                        progress.onProgress(offset * 100 / total, "Compressing...");
                }
            }
        }
    }

    // ─── getRecipientKeyIds ────────────────────────────────────────

    public List<Long> getRecipientKeyIds(byte[] cipherData) throws Exception {
        try (InputStream in = openInput(cipherData)) {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
            Object o = pgpFact.nextObject();

            PGPEncryptedDataList encList;
            if (o instanceof PGPEncryptedDataList) {
                encList = (PGPEncryptedDataList) o;
            } else {
                encList = (PGPEncryptedDataList) pgpFact.nextObject();
            }

            List<Long> ids = new ArrayList<>();
            Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
            while (it.hasNext()) {
                PGPEncryptedData ed = it.next();
                if (ed instanceof PGPPublicKeyEncryptedData) {
                    ids.add(((PGPPublicKeyEncryptedData) ed).getKeyID());
                }
            }
            return ids;
        }
    }

    // ─── Decrypt (byte[] → DecryptResult with compound) ───────────

    public DecryptResult decrypt(byte[] cipherData,
                                  List<PGPSecretKey> secretKeys,
                                  List<PGPPublicKey> publicKeys,
                                  Map<Long, String> publicKeyUserIdByKeyId,
                                  Map<Long, String> secretKeyUserIds,
                                  ProgressCallback progress,
                                  boolean decodeText) throws Exception {
        Path tempFile = Files.createTempFile("pgp-decrypt-", ".bin");
        try {
            DecryptResult result = decryptToFile(cipherData, tempFile, secretKeys, publicKeys,
                    publicKeyUserIdByKeyId, secretKeyUserIds, progress, decodeText);
            return result;
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    // ─── Decrypt stream (byte[] → DecryptResult with temp file) ──

    public DecryptResult decryptToFile(byte[] cipherData, Path tempFile,
                                        List<PGPSecretKey> secretKeys,
                                        List<PGPPublicKey> publicKeys,
                                        Map<Long, String> publicKeyUserIdByKeyId,
                                        Map<Long, String> secretKeyUserIds,
                                        ProgressCallback progress,
                                        boolean decodeText) throws Exception {
        try (InputStream in = openInput(cipherData, progress)) {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
            return doDecryptToFile(pgpFact, tempFile, secretKeys, publicKeys,
                    publicKeyUserIdByKeyId, secretKeyUserIds, decodeText);
        }
    }

    public DecryptResult decryptPasswordToFile(byte[] data, char[] password, Path tempFile,
                                                 List<PGPPublicKey> publicKeys,
                                                 Map<Long, String> publicKeyUserIdByKeyId,
                                                 ProgressCallback progress,
                                                 boolean decodeText) throws Exception {
        try (InputStream in = openInput(data, progress)) {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList encList = (PGPEncryptedDataList) pgpFact.nextObject();
            PGPPBEEncryptedData encData = null;
            Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
            while (it.hasNext()) {
                PGPEncryptedData ed = it.next();
                if (ed instanceof PGPPBEEncryptedData) {
                    encData = (PGPPBEEncryptedData) ed;
                    break;
                }
            }
            if (encData == null) throw new PGPException("No PBE encrypted data found");

            PBEDataDecryptorFactory pbeFactory = new JcePBEDataDecryptorFactoryBuilder()
                    .setProvider("BC").build(password);
            InputStream clearStream = encData.getDataStream(pbeFactory);

            DecryptResult.Metadata.Builder metaBuilder = new DecryptResult.Metadata.Builder()
                    .encryptionAlgorithm(encData.getSymmetricAlgorithm(pbeFactory));
            return parseDecryptedStreamToFile(clearStream, metaBuilder, tempFile, publicKeys, publicKeyUserIdByKeyId, decodeText);
        }
    }

    public DecryptResult decryptCompressToFile(byte[] data, Path tempFile,
                                                 List<PGPPublicKey> publicKeys,
                                                 Map<Long, String> publicKeyUserIdByKeyId,
                                                 ProgressCallback progress,
                                                 boolean decodeText) throws Exception {
        try (InputStream in = openInput(data, progress)) {
            DecryptResult.Metadata.Builder metaBuilder = new DecryptResult.Metadata.Builder();
            return parseDecryptedStreamToFile(in, metaBuilder, tempFile, publicKeys, publicKeyUserIdByKeyId, decodeText);
        }
    }

    // ─── PBE detection ────────────────────────────────────────────

    public boolean isPBE(byte[] data) throws Exception {
        try (InputStream in = openInput(data)) {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
            Object o = pgpFact.nextObject();
            if (o instanceof PGPEncryptedDataList) {
                Iterator<PGPEncryptedData> it = ((PGPEncryptedDataList) o).getEncryptedDataObjects();
                while (it.hasNext()) {
                    if (it.next() instanceof PGPPBEEncryptedData) return true;
                }
            }
            return false;
        }
    }

    public boolean isUnencrypted(byte[] data) throws Exception {
        try (InputStream in = openInput(data)) {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
            return !(pgpFact.nextObject() instanceof PGPEncryptedDataList);
        }
    }

    // ─── DecryptPassword (byte[] → DecryptResult) ─────────────────

    public DecryptResult decryptPassword(byte[] data, char[] password,
                                           List<PGPPublicKey> publicKeys,
                                           Map<Long, String> publicKeyUserIdByKeyId,
                                           ProgressCallback progress,
                                           boolean decodeText) throws Exception {
        Path tempFile = Files.createTempFile("pgp-decrypt-pbe-", ".bin");
        try {
            return decryptPasswordToFile(data, password, tempFile, publicKeys, publicKeyUserIdByKeyId, progress, decodeText);
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    public DecryptResult decryptCompress(byte[] data,
                                           List<PGPPublicKey> publicKeys,
                                           Map<Long, String> publicKeyUserIdByKeyId,
                                           ProgressCallback progress,
                                           boolean decodeText) throws Exception {
        Path tempFile = Files.createTempFile("pgp-decompress-", ".bin");
        try {
            return decryptCompressToFile(data, tempFile, publicKeys, publicKeyUserIdByKeyId, progress, decodeText);
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    // ─── openInput ────────────────────────────────────────────────

    private InputStream openInput(byte[] data) throws Exception {
        return openInput(data, null);
    }

    private InputStream openInput(byte[] data, ProgressCallback progress) throws Exception {
        String header = new String(data, 0, Math.min(data.length, 50), StandardCharsets.US_ASCII).trim();
        InputStream in;
        if (header.startsWith("-----BEGIN PGP")) {
            in = new ArmoredInputStream(new ByteArrayInputStream(data));
        } else {
            in = new ByteArrayInputStream(data);
        }
        if (progress != null)
            in = new CountingInputStream(in, data.length, progress);
        return in;
    }

    // ─── CountingInputStream ──────────────────────────────────────

    private static class CountingInputStream extends InputStream {
        private final InputStream delegate;
        private final int total;
        private final ProgressCallback progress;
        private int count;
        CountingInputStream(InputStream delegate, int total, ProgressCallback progress) {
            this.delegate = delegate;
            this.total = total;
            this.progress = progress;
        }
        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int n = delegate.read(one, 0, 1);
            if (n > 0) { count++; tick(); }
            return n > 0 ? one[0] & 0xFF : -1;
        }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            int n = delegate.read(b, off, len);
            if (n > 0) { count += n; tick(); }
            return n;
        }
        @Override public void close() throws IOException { delegate.close(); }
        private void tick() {
            if (progress != null) {
                int pct = Math.min(count * 100 / Math.max(total, 1), 100);
                progress.onProgress(pct, "Decrypting...");
            }
        }
    }

    // ─── doDecrypt (byte[] metadata) ───────────────────────────────

    private DecryptResult doDecryptToFile(JcaPGPObjectFactory pgpFact, Path tempFile,
                                           List<PGPSecretKey> secretKeys,
                                           List<PGPPublicKey> publicKeys,
                                           Map<Long, String> publicKeyUserIdByKeyId,
                                           Map<Long, String> secretKeyUserIds,
                                           boolean decodeText) throws Exception {
        Object o = pgpFact.nextObject();

        PGPEncryptedDataList encList;
        if (o instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) o;
        } else {
            encList = (PGPEncryptedDataList) pgpFact.nextObject();
        }

        PGPPublicKeyEncryptedData encData = null;
        PGPSecretKey secKey = null;

        List<Long> allRecipientIds = new ArrayList<>();
        Iterator<PGPEncryptedData> listIt = encList.getEncryptedDataObjects();
        while (listIt.hasNext()) {
            PGPEncryptedData ed = listIt.next();
            if (ed instanceof PGPPublicKeyEncryptedData) {
                allRecipientIds.add(((PGPPublicKeyEncryptedData) ed).getKeyID());
            }
        }

        for (PGPSecretKey sk : secretKeys) {
            for (long rid : allRecipientIds) {
                if (sk.getKeyID() == rid) {
                    encData = findEncDataById(encList, rid);
                    secKey = sk;
                    break;
                }
            }
            if (encData != null) break;
        }

        if (encData == null) {
            throw new PGPException("No matching private key found for this message");
        }

        char[] passphrase = passphraseCache.get(secKey.getKeyID());
        if (passphrase == null) {
            throw new PGPException("Passphrase required but not provided");
        }

        PGPPrivateKey privateKey = secKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));

        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(privateKey);

        DecryptResult.Metadata.Builder metaBuilder = new DecryptResult.Metadata.Builder()
                .recipientKeyId(encData.getKeyID())
                .allRecipientKeyIds(allRecipientIds)
                .encryptionAlgorithm(encData.getSymmetricAlgorithm(decryptorFactory))
                .recipientUserId(secretKeyUserIds != null ? secretKeyUserIds.get(encData.getKeyID()) : null);

        InputStream clearStream = encData.getDataStream(decryptorFactory);

        return parseDecryptedStreamToFile(clearStream, metaBuilder, tempFile, publicKeys, publicKeyUserIdByKeyId, decodeText);
    }

    // ─── parseDecryptedStream → temp file ────────────────────────

    private DecryptResult parseDecryptedStreamToFile(InputStream clearStream,
                                                       DecryptResult.Metadata.Builder metaBuilder,
                                                       Path tempFile,
                                                       List<PGPPublicKey> publicKeys,
                                                       Map<Long, String> publicKeyUserIdByKeyId,
                                                       boolean decodeText) throws Exception {
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clearStream);
        Object message = plainFact.nextObject();

        DecryptResult result;

        if (message instanceof PGPCompressedData) {
            PGPCompressedData compData = (PGPCompressedData) message;
            metaBuilder.compressionAlgorithm(compData.getAlgorithm());
            InputStream compStream = compData.getDataStream();
            plainFact = new JcaPGPObjectFactory(compStream);
            result = parseCompressedToFile(plainFact, metaBuilder, tempFile, publicKeys, publicKeyUserIdByKeyId, decodeText);
        } else if (message instanceof PGPOnePassSignatureList || message instanceof PGPLiteralData) {
            result = parseCompressedToFile(plainFact, metaBuilder, tempFile, publicKeys, publicKeyUserIdByKeyId, decodeText);
        } else {
            throw new PGPException("Unexpected PGP message format: " + (message != null ? message.getClass().getName() : "null"));
        }

        byte[] drainBuf = new byte[8192];
        while (clearStream.read(drainBuf) >= 0) {}
        return result;
    }

    // ─── parseCompressed → temp file ─────────────────────────────

    private DecryptResult parseCompressedToFile(JcaPGPObjectFactory plainFact,
                                                  DecryptResult.Metadata.Builder metaBuilder,
                                                  Path tempFile,
                                                  List<PGPPublicKey> publicKeys,
                                                  Map<Long, String> publicKeyUserIdByKeyId,
                                                  boolean decodeText) throws Exception {
        Object message = plainFact.nextObject();

        if (message instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList opsList = (PGPOnePassSignatureList) message;
            PGPOnePassSignature ops = opsList.get(0);
            long signerKeyId = ops.getKeyID();

            PGPPublicKey pubKey = findPublicKeyById(publicKeys, signerKeyId);

            PGPLiteralData litData = (PGPLiteralData) plainFact.nextObject();
            metaBuilder.literalFormat((char) litData.getFormat())
                       .fileName(litData.getFileName())
                       .modificationTime(litData.getModificationTime());

            // Write literal data to temp file
            InputStream litStream = litData.getDataStream();
            long totalWritten = 0;
            try (OutputStream fileOut = Files.newOutputStream(tempFile)) {
                byte[] buf = new byte[CHUNK_SIZE];
                int n;
                while ((n = litStream.read(buf)) >= 0) {
                    fileOut.write(buf, 0, n);
                    totalWritten += n;
                }
            }
            byte[] rawData = totalWritten <= Integer.MAX_VALUE && totalWritten <= 50_000_000
                    ? Files.readAllBytes(tempFile) : null;

            PGPSignatureList sigList = (PGPSignatureList) plainFact.nextObject();
            PGPSignature sig = sigList.get(0);
            fillSignatureMeta(metaBuilder, sig);

            CompoundMessage compound = null;
            String plainText;
            if (totalWritten > 0) {
                if (rawData != null && rawData.length >= 4 && CompoundCodec.isCompound(rawData)) {
                    try (InputStream decodeIn = Files.newInputStream(tempFile)) {
                        compound = CompoundCodec.decode(decodeIn, (int) totalWritten, tempFile);
                    }
                    plainText = compound.getPlainText();
                } else if (rawData != null && decodeText) {
                    plainText = new String(rawData, StandardCharsets.UTF_8);
                } else {
                    plainText = "";
                }
            } else {
                plainText = "";
            }

            if (pubKey != null) {
                if (publicKeyUserIdByKeyId != null) {
                    String uid = publicKeyUserIdByKeyId.get(signerKeyId);
                    if (uid != null) metaBuilder.signerUserId(uid);
                }
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);
                ops.update(rawData != null ? rawData : Files.readAllBytes(tempFile));

                boolean verified = ops.verify(sig);
                DecryptResult.VerificationStatus status = verified
                        ? DecryptResult.VerificationStatus.SIGNED_VERIFIED
                        : DecryptResult.VerificationStatus.SIGNED_INVALID;
                return new DecryptResult(plainText, rawData, status, signerKeyId, metaBuilder.build(), compound, tempFile);
            } else {
                return new DecryptResult(plainText, rawData,
                        DecryptResult.VerificationStatus.SIGNED_KEY_NOT_FOUND, signerKeyId, metaBuilder.build(), compound, tempFile);
            }
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData litData = (PGPLiteralData) message;
            metaBuilder.literalFormat((char) litData.getFormat())
                       .fileName(litData.getFileName())
                       .modificationTime(litData.getModificationTime());

            // Write literal data to temp file
            InputStream litStream = litData.getDataStream();
            long totalWritten;
            try (OutputStream fileOut = Files.newOutputStream(tempFile)) {
                byte[] buf = new byte[CHUNK_SIZE];
                int n;
                while ((n = litStream.read(buf)) >= 0) {
                    fileOut.write(buf, 0, n);
                }
                totalWritten = Files.size(tempFile);
            }
            byte[] rawData = totalWritten <= Integer.MAX_VALUE && totalWritten <= 50_000_000
                    ? Files.readAllBytes(tempFile) : null;

            CompoundMessage compound = null;
            String plainText;
            if (totalWritten > 0) {
                if (rawData != null && rawData.length >= 4 && CompoundCodec.isCompound(rawData)) {
                    try (InputStream decodeIn = Files.newInputStream(tempFile)) {
                        compound = CompoundCodec.decode(decodeIn, (int) totalWritten, tempFile);
                    }
                    plainText = compound.getPlainText();
                } else if (rawData != null && decodeText) {
                    plainText = new String(rawData, StandardCharsets.UTF_8);
                } else {
                    plainText = "";
                }
            } else {
                plainText = "";
            }

            return new DecryptResult(plainText, rawData,
                    DecryptResult.VerificationStatus.NOT_SIGNED, null, metaBuilder.build(), compound, tempFile);
        }

        throw new PGPException("Unexpected packet: " + (message != null ? message.getClass().getName() : "null"));
    }

    // ─── Signature metadata ──────────────────────────────────────

    private void fillSignatureMeta(DecryptResult.Metadata.Builder metaBuilder, PGPSignature sig) {
        metaBuilder.signerKeyId(sig.getKeyID())
                   .hashAlgorithm(sig.getHashAlgorithm());
        try {
            String uid = null;
            Date creationTime = null;
            PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
            if (sv != null) {
                uid = sv.getSignerUserID();
                if (sv.getSignatureCreationTime() != null)
                    creationTime = sv.getSignatureCreationTime();
            }
            if (uid == null || creationTime == null) {
                PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();
                if (unhashed != null) {
                    if (uid == null) uid = unhashed.getSignerUserID();
                    if (creationTime == null && unhashed.getSignatureCreationTime() != null)
                        creationTime = unhashed.getSignatureCreationTime();
                }
            }
            if (uid != null) metaBuilder.signerUserId(uid);
            if (creationTime != null) metaBuilder.signatureCreationTime(creationTime);
        } catch (Exception ignored) {}
    }

    private PGPPublicKey findPublicKeyById(List<PGPPublicKey> keys, long keyId) {
        if (keys == null) return null;
        for (PGPPublicKey key : keys) {
            if (key.getKeyID() == keyId) return key;
        }
        return null;
    }

    private PGPPublicKeyEncryptedData findEncDataById(PGPEncryptedDataList encList, long keyId) {
        Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
        while (it.hasNext()) {
            PGPEncryptedData ed = it.next();
            if (ed instanceof PGPPublicKeyEncryptedData
                    && ((PGPPublicKeyEncryptedData) ed).getKeyID() == keyId) {
                return (PGPPublicKeyEncryptedData) ed;
            }
        }
        return null;
    }

    public void cachePassphrase(long keyId, char[] passphrase) {
        passphraseCache.put(keyId, passphrase);
    }

    public boolean hasPassphrase(long keyId) {
        return passphraseCache.containsKey(keyId);
    }

    public boolean cacheEmptyPassphraseIfUnprotected(PGPSecretKey key) {
        try {
            key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(new char[0]));
            cachePassphrase(key.getKeyID(), new char[0]);
            return true;
        } catch (PGPException e) {
            return false;
        }
    }

    public char[] getPassphraseFor(long keyId) {
        return passphraseCache.get(keyId);
    }

    public void clearPassphraseCache() {
        passphraseCache.clear();
    }
}
