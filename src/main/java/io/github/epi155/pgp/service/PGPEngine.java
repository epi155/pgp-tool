package io.github.epi155.pgp.service;

import io.github.epi155.pgp.model.CompoundCodec;
import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.DecryptResult;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

public class PGPEngine {

    private static final int CHUNK_SIZE = 65536;

    private final Map<Long, char[]> passphraseCache = new HashMap<>();
    private PassphraseProvider passphraseProvider;
    private PasswordProvider passwordProvider;

    @FunctionalInterface
    public interface PassphraseProvider {
        char[] getPassphraseFor(long keyId);
    }

    @FunctionalInterface
    public interface PasswordProvider {
        char[] getPasswordForLayer(int layerIndex);
    }

    public void setPassphraseProvider(PassphraseProvider provider) {
        this.passphraseProvider = provider;
    }

    public void setPasswordProvider(PasswordProvider provider) {
        this.passwordProvider = provider;
    }

    // ─── Encrypt stream (byte[] → OutputStream) ───────────────────

    public void encrypt(byte[] data, String fileName, OutputStream out,
                        List<PGPPublicKey> encKeys, List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                        int symmetricAlgorithm, int compressionAlgorithm,
                        List<Integer> hashAlgorithms, boolean armor,
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
                    writeSignAndLiteral(zipOut, data, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
                }
            }
        }
    }

    public void encryptRaw(byte[] data, OutputStream out,
                            List<PGPPublicKey> encKeys, int symmetricAlgorithm,
                            boolean armor,
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
                encOut.write(data);
            }
        }
    }

    public void encryptRawPassword(byte[] data, OutputStream out,
                                    char[] password, int symmetricAlgorithm,
                                    boolean armor,
                                    ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                    new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                            .setWithIntegrityPacket(true)
                            .setSecureRandom(new SecureRandom())
                            .setProvider("BC"));
            encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(password).setProvider("BC"));
            try (OutputStream encOut = encGen.open(armored, new byte[CHUNK_SIZE])) {
                encOut.write(data);
            }
        }
    }

    public void encryptPassword(byte[] data, String fileName, OutputStream out,
                                 char[] password, List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                 int symmetricAlgorithm, int compressionAlgorithm,
                                 List<Integer> hashAlgorithms, boolean armor,
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
                    writeSignAndLiteral(zipOut, data, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
                }
            }
        }
    }

    public void encryptCompress(byte[] data, String fileName, OutputStream out,
                                 List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                 int compressionAlgorithm,
                                 List<Integer> hashAlgorithms, boolean armor,
                                 ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(compressionAlgorithm);
            try (OutputStream zipOut = comData.open(armored)) {
                writeSignAndLiteral(zipOut, data, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
            }
        }
    }

    // ─── hash algorithm override per key type ─────────────────────

    private static int defaultHashForAlgo(int keyAlgorithm, int fallback) {
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed25519) return HashAlgorithmTags.SHA512;
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed448) return Ed448PGPContentSignerBuilder.SHAKE256;
        return fallback;
    }

    // ─── writeSignAndLiteral (byte[]) ─────────────────────────────

    private void writeSignAndLiteral(OutputStream out, byte[] data, String fileName,
                                      List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                      List<Integer> hashAlgorithms,
                                      ProgressCallback progress) throws Exception {
        int total = data.length;
        if (signKeys != null && !signKeys.isEmpty()) {
            List<PGPSignatureGenerator> sigGens = new ArrayList<>();
            for (int i = 0; i < signKeys.size(); i++) {
                char[] passphrase = signPassphrases != null && i < signPassphrases.size()
                        ? signPassphrases.get(i) : null;
                PGPPrivateKey signPrivateKey = signKeys.get(i).extractPrivateKey(
                        new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
                PGPPublicKey signPubKey = signKeys.get(i).getPublicKey();
                int userHash = (hashAlgorithms != null && i < hashAlgorithms.size())
                    ? hashAlgorithms.get(i) : HashAlgorithmTags.SHA256;
                int effectiveHash = defaultHashForAlgo(signPubKey.getAlgorithm(), userHash);
                PGPContentSignerBuilder csBuilder;
                if (signPubKey.getAlgorithm() == PublicKeyAlgorithmTags.Ed448) {
                    csBuilder = new Ed448PGPContentSignerBuilder(effectiveHash);
                } else {
                    csBuilder = new JcaPGPContentSignerBuilder(signPubKey.getAlgorithm(), effectiveHash)
                            .setProvider("BC");
                }
                PGPSignatureGenerator sigGen = new PGPSignatureGenerator(csBuilder);
                sigGen.init(PGPSignature.BINARY_DOCUMENT, signPrivateKey);
                sigGen.generateOnePassVersion(false).encode(out);
                sigGens.add(sigGen);
            }
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            try (OutputStream litOut = litGen.open(out, PGPLiteralData.BINARY,
                    fileName, total, new Date())) {
                int offset = 0;
                while (offset < total) {
                    int chunk = Math.min(CHUNK_SIZE, total - offset);
                    for (PGPSignatureGenerator sigGen : sigGens) {
                        sigGen.update(data, offset, chunk);
                    }
                    litOut.write(data, offset, chunk);
                    offset += chunk;
                    if (progress != null)
                        progress.onProgress(offset * 100 / total, "Encrypting...");
                }
            }
            for (PGPSignatureGenerator sigGen : sigGens) {
                sigGen.generate().encode(out);
            }
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

    // ─── Nested decryption (unified entry point) ─────────────────

    public DecryptResult decryptNested(byte[] cipherData,
                                        List<PGPSecretKey> secretKeys,
                                        List<PGPPublicKey> publicKeys,
                                        Map<Long, String> publicKeyUserIdByKeyId,
                                        Map<Long, String> secretKeyUserIds,
                                        List<char[]> pbePasswords,
                                        ProgressCallback progress,
                                        boolean decodeText) throws Exception {
        Path tempFile = Files.createTempFile("pgp-nested-decrypt-", ".bin");
        try {
            return decryptNestedToFile(cipherData, tempFile, secretKeys, publicKeys,
                    publicKeyUserIdByKeyId, secretKeyUserIds, pbePasswords, progress, decodeText);
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    public DecryptResult decryptNestedToFile(byte[] cipherData, Path tempFile,
                                              List<PGPSecretKey> secretKeys,
                                              List<PGPPublicKey> publicKeys,
                                              Map<Long, String> publicKeyUserIdByKeyId,
                                              Map<Long, String> secretKeyUserIds,
                                              List<char[]> pbePasswords,
                                              ProgressCallback progress,
                                              boolean decodeText) throws Exception {
        try (InputStream in = openInput(cipherData, progress)) {
            List<DecryptResult.EncryptionLayer> encLayers = new ArrayList<>();
            DecryptResult.Metadata.Builder metaBuilder = new DecryptResult.Metadata.Builder();
            return parseDecryptedStreamToFile(in, encLayers, metaBuilder, tempFile,
                    secretKeys, publicKeys, publicKeyUserIdByKeyId, secretKeyUserIds,
                    pbePasswords, decodeText);
        }
    }

    public Set<Long> getAllRecipientKeyIdsRecursive(byte[] cipherData) throws Exception {
        Set<Long> allIds = new HashSet<>();
        collectRecipientKeyIds(cipherData, allIds);
        return allIds;
    }

    private void collectRecipientKeyIds(byte[] data, Set<Long> allIds) throws Exception {
        try (InputStream in = openInput(data)) {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);
            Object o = factory.nextObject();
            if (o instanceof PGPEncryptedDataList) {
                PGPEncryptedDataList encList = (PGPEncryptedDataList) o;
                for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
                    PGPEncryptedData ed = it.next();
                    if (ed instanceof PGPPublicKeyEncryptedData) {
                        allIds.add(((PGPPublicKeyEncryptedData) ed).getKeyID());
                    }
                }
            }
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

    // ─── parseDecryptedStream → temp file (recursive) ────────────

    private DecryptResult parseDecryptedStreamToFile(InputStream clearStream,
                                                       List<DecryptResult.EncryptionLayer> encLayers,
                                                       DecryptResult.Metadata.Builder metaBuilder,
                                                       Path tempFile,
                                                       List<PGPSecretKey> secretKeys,
                                                       List<PGPPublicKey> publicKeys,
                                                       Map<Long, String> publicKeyUserIdByKeyId,
                                                       Map<Long, String> secretKeyUserIds,
                                                       List<char[]> pbePasswords,
                                                       boolean decodeText) throws Exception {
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clearStream);
        Object message = plainFact.nextObject();

        // Nested encryption layer
        if (message instanceof PGPEncryptedDataList) {
            InputStream innerStream = decryptLayer((PGPEncryptedDataList) message, encLayers,
                    secretKeys, secretKeyUserIds, pbePasswords);
            return parseDecryptedStreamToFile(innerStream, encLayers, metaBuilder, tempFile,
                    secretKeys, publicKeys, publicKeyUserIdByKeyId, secretKeyUserIds,
                    pbePasswords, decodeText);
        }

        // Inner content
        if (message instanceof PGPCompressedData) {
            PGPCompressedData compData = (PGPCompressedData) message;
            metaBuilder.compressionAlgorithm(compData.getAlgorithm());
            InputStream compStream = compData.getDataStream();
            plainFact = new JcaPGPObjectFactory(compStream);
        }

        // Build final Metadata with encryption layers info
        if (!encLayers.isEmpty()) {
            metaBuilder.encryptionLayers(encLayers);
            // Backward compat: populate single-layer fields from deepest public-key layer
            for (int i = encLayers.size() - 1; i >= 0; i--) {
                DecryptResult.EncryptionLayer layer = encLayers.get(i);
                if (layer.getType() == DecryptResult.EncryptionLayer.Type.PUBLIC_KEY) {
                    metaBuilder.recipientKeyId(layer.getRecipientKeyId());
                    metaBuilder.allRecipientKeyIds(layer.getAllRecipientKeyIds());
                    metaBuilder.encryptionAlgorithm(layer.getEncryptionAlgorithm());
                    metaBuilder.publicKeyAlgorithm(layer.getPublicKeyAlgorithm());
                    if (layer.getRecipientUserId() != null)
                        metaBuilder.recipientUserId(layer.getRecipientUserId());
                    break;
                }
            }
            // If no public-key layer, use encryption algo from the last layer
            if (metaBuilder.getEncryptionAlgorithm() == null) {
                metaBuilder.encryptionAlgorithm(
                    encLayers.get(encLayers.size() - 1).getEncryptionAlgorithm());
            }
        }

        return parseCompressedToFile(plainFact, metaBuilder, tempFile,
                publicKeys, publicKeyUserIdByKeyId, decodeText);
    }

    private InputStream decryptLayer(PGPEncryptedDataList encList,
                                      List<DecryptResult.EncryptionLayer> encLayers,
                                      List<PGPSecretKey> secretKeys,
                                      Map<Long, String> secretKeyUserIds,
                                      List<char[]> pbePasswords) throws Exception {
        // Try PBE if passwords are available
        if (pbePasswords != null && !pbePasswords.isEmpty()) {
            for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
                PGPEncryptedData ed = it.next();
                if (ed instanceof PGPPBEEncryptedData) {
                    char[] password = pbePasswords.remove(0);
                    PBEDataDecryptorFactory pbeFactory = new JcePBEDataDecryptorFactoryBuilder()
                            .setProvider("BC").build(password);
                    int symAlgo = ((PGPPBEEncryptedData) ed).getSymmetricAlgorithm(pbeFactory);
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PASSWORD, symAlgo, 0,
                            null, null, null));
                    return ((PGPPBEEncryptedData) ed).getDataStream(pbeFactory);
                }
            }
        }

        // On-demand PBE password via provider (for nested/hybrid layers)
        if (passwordProvider != null) {
            for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
                PGPEncryptedData ed = it.next();
                if (ed instanceof PGPPBEEncryptedData) {
                    char[] password = passwordProvider.getPasswordForLayer(encLayers.size() + 1);
                    if (password == null) {
                        throw new PGPException("Password prompt cancelled");
                    }
                    PBEDataDecryptorFactory pbeFactory = new JcePBEDataDecryptorFactoryBuilder()
                            .setProvider("BC").build(password);
                    int symAlgo = ((PGPPBEEncryptedData) ed).getSymmetricAlgorithm(pbeFactory);
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PASSWORD, symAlgo, 0,
                            null, null, null));
                    return ((PGPPBEEncryptedData) ed).getDataStream(pbeFactory);
                }
            }
        }

        // Public-key layer
        List<Long> allRecipientIds = new ArrayList<>();
        for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
            PGPEncryptedData ed = it.next();
            if (ed instanceof PGPPublicKeyEncryptedData) {
                allRecipientIds.add(((PGPPublicKeyEncryptedData) ed).getKeyID());
            }
        }

        if (secretKeys == null || secretKeys.isEmpty()) {
            throw new PGPException("No private keys available for an encryption layer");
        }

        boolean dialogShown = false;
        Exception lastError = null;
        
        for (PGPSecretKey sk : secretKeys) {
            for (long rid : allRecipientIds) {
                if (sk.getKeyID() != rid) continue;

                char[] passphrase = passphraseCache.get(sk.getKeyID());
                if (passphrase == null) {
                    try {
                        extractPrivateKey(sk, new char[0]);
                        passphrase = new char[0];
                    } catch (Exception ignored) {
                        if (!dialogShown && passphraseProvider != null) {
                            passphrase = passphraseProvider.getPassphraseFor(sk.getKeyID());
                            if (passphrase == null) dialogShown = true;
                        }
                    }
                }
                if (passphrase == null) continue;

                try {
                    PGPPrivateKey privateKey = extractPrivateKey(sk, passphrase);
                    passphraseCache.put(sk.getKeyID(), passphrase);

                    PGPPublicKeyEncryptedData encData = findEncDataById(encList, rid);
                    InputStream clearStream;
                    int symAlgo;
                    try {
                        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                                .setProvider("BC").build(privateKey);
                        symAlgo = encData.getSymmetricAlgorithm(decryptorFactory);
                        clearStream = encData.getDataStream(decryptorFactory);
                    } catch (Exception e) {
                        PublicKeyDataDecryptorFactory decryptorFactory = new BcPublicKeyDataDecryptorFactory(privateKey);
                        symAlgo = encData.getSymmetricAlgorithm(decryptorFactory);
                        clearStream = encData.getDataStream(decryptorFactory);
                    }
                    String uid = secretKeyUserIds != null ? secretKeyUserIds.get(encData.getKeyID()) : null;
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PUBLIC_KEY, symAlgo,
                            sk.getPublicKey().getAlgorithm(),
                            encData.getKeyID(), allRecipientIds, uid));

                    return clearStream;
                } catch (Exception e) {
                    lastError = e;
                }
            }
        }

        if (lastError != null) throw lastError;
        String keyIds = allRecipientIds.stream()
                .map(id -> String.format("0x%08X", id))
                .reduce((a, b) -> a + ", " + b)
                .orElse("");
        throw new PGPException("No matching private key found.\n"
                + "Key IDs required by the message: " + keyIds);
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
            // Read literal data (comes after OPS, before signatures)
            PGPLiteralData litData = (PGPLiteralData) plainFact.nextObject();
            if (litData == null) {
                throw new PGPException("Missing literal data packet");
            }
            metaBuilder.literalFormat((char) litData.getFormat())
                       .fileName(litData.getFileName())
                       .modificationTime(litData.getModificationTime());
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
            byte[] verifyData = rawData != null ? rawData : Files.readAllBytes(tempFile);
            // Now read the trailing signature list
            PGPSignatureList sigList = (PGPSignatureList) plainFact.nextObject();

            // Build keyId → signature map (order may differ from OPS)
            Map<Long, PGPSignature> sigByKeyId = new HashMap<>();
            if (sigList != null) {
                for (int i = 0; i < sigList.size(); i++) {
                    PGPSignature s = sigList.get(i);
                    sigByKeyId.put(s.getKeyID(), s);
                }
            }

            List<DecryptResult.SignerInfo> signers = new ArrayList<>();
            DecryptResult.VerificationStatus overallStatus = DecryptResult.VerificationStatus.SIGNED_VERIFIED;

            for (int i = 0; i < opsList.size(); i++) {
                PGPOnePassSignature ops = opsList.get(i);
                long signerKeyId = ops.getKeyID();
                PGPPublicKey pubKey = findPublicKeyById(publicKeys, signerKeyId);

                String userId = null;
                if (pubKey != null && publicKeyUserIdByKeyId != null) {
                    userId = publicKeyUserIdByKeyId.get(signerKeyId);
                }

                int sigHashAlgo = 0;
                Date sigTime = null;
                String sigUserId = null;
                DecryptResult.VerificationStatus signerStatus;

                PGPSignature sig = sigByKeyId.get(signerKeyId);

                if (pubKey == null) {
                    signerStatus = DecryptResult.VerificationStatus.SIGNED_KEY_NOT_FOUND;
                    overallStatus = DecryptResult.VerificationStatus.SIGNED_KEY_NOT_FOUND;
                } else if (sig == null) {
                    signerStatus = DecryptResult.VerificationStatus.SIGNED_INVALID;
                    overallStatus = DecryptResult.VerificationStatus.SIGNED_INVALID;
                } else {
                    sigHashAlgo = sig.getHashAlgorithm();
                    try {
                        PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
                        if (sv != null) {
                            sigUserId = sv.getSignerUserID();
                            if (sv.getSignatureCreationTime() != null)
                                sigTime = sv.getSignatureCreationTime();
                        }
                        if (sigUserId == null || sigTime == null) {
                            PGPSignatureSubpacketVector unhashed = sig.getUnhashedSubPackets();
                            if (unhashed != null) {
                                if (sigUserId == null) sigUserId = unhashed.getSignerUserID();
                                if (sigTime == null && unhashed.getSignatureCreationTime() != null)
                                    sigTime = unhashed.getSignatureCreationTime();
                            }
                        }
                    } catch (Exception ignored) {}

                    ops.init(new Ed448PGPContentVerifierBuilderProvider(), pubKey);
                    ops.update(verifyData);
                    boolean verified = ops.verify(sig);
                    signerStatus = verified
                            ? DecryptResult.VerificationStatus.SIGNED_VERIFIED
                            : DecryptResult.VerificationStatus.SIGNED_INVALID;
                    if (!verified) {
                        overallStatus = DecryptResult.VerificationStatus.SIGNED_INVALID;
                    }
                }

                signers.add(new DecryptResult.SignerInfo(
                        signerKeyId, signerStatus,
                        userId != null ? userId : sigUserId,
                        sigHashAlgo, ops.getKeyAlgorithm(),
                        sigTime));
            }

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

            // Use first signer keyId for backward compat Metadata
            if (!signers.isEmpty()) {
                long firstKeyId = signers.get(0).getKeyId();
                metaBuilder.signerKeyId(firstKeyId);
                metaBuilder.hashAlgorithm(signers.get(0).getHashAlgorithm());
                if (signers.get(0).getSignatureTime() != null)
                    metaBuilder.signatureCreationTime(signers.get(0).getSignatureTime());
                if (signers.get(0).getUserId() != null)
                    metaBuilder.signerUserId(signers.get(0).getUserId());
            }

            return new DecryptResult(plainText, rawData, overallStatus, signers,
                    metaBuilder.build(), compound, tempFile);
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
            extractPrivateKey(key, new char[0]);
            cachePassphrase(key.getKeyID(), new char[0]);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public char[] getPassphraseFor(long keyId) {
        return passphraseCache.get(keyId);
    }

    public void clearPassphraseCache() {
        passphraseCache.clear();
    }

    private PGPPrivateKey extractPrivateKey(PGPSecretKey key, char[] passphrase) throws PGPException {
        try {
            return key.extractPrivateKey(
                    new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase));
        } catch (Exception e1) {
            try {
                return key.extractPrivateKey(
                        new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passphrase));
            } catch (Exception e2) {
                if (key.getKeyEncryptionAlgorithm() == SymmetricKeyAlgorithmTags.NULL) {
                    throw new PGPException("manual extraction not available in this API version");
                }
                throw new PGPException("failed to extract private key", e2);
            }
        }
    }
}
