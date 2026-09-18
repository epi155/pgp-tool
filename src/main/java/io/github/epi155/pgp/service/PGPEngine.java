package io.github.epi155.pgp.service;

import io.github.epi155.pgp.model.CompoundCodec;
import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.DecryptResult;
import io.github.epi155.pgp.model.TarArchive;
import io.github.epi155.pgp.model.TarCodec;
import io.github.epi155.pgp.model.DecryptResult;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.*;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
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
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            for (PGPPublicKey key : encKeys) {
                methods.add(createPublicKeyMethod(key));
            }
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayer(encOut, data, fileName, signKeys, signPassphrases,
                        compressionAlgorithm, hashAlgorithms, progress);
            }
        }
    }

    public void encryptRaw(byte[] data, OutputStream out,
                            List<PGPPublicKey> encKeys, int symmetricAlgorithm,
                            boolean armor,
                            ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            for (PGPPublicKey key : encKeys) {
                methods.add(createPublicKeyMethod(key));
            }
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                encOut.write(data);
            }
        }
    }

    public void encryptRawPassword(byte[] data, OutputStream out,
                                    char[] password, int symmetricAlgorithm,
                                    boolean armor,
                                    ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            methods.add(createPBEMethod(password, symmetricAlgorithm));
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
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
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            methods.add(createPBEMethod(password, symmetricAlgorithm));
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayer(encOut, data, fileName, signKeys, signPassphrases,
                        compressionAlgorithm, hashAlgorithms, progress);
            }
        }
    }

    public void encrypt(TarArchive tarArchive, String fileName, OutputStream out,
                         List<PGPPublicKey> encKeys, List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                         int symmetricAlgorithm, int compressionAlgorithm,
                         List<Integer> hashAlgorithms, boolean armor,
                         ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            for (PGPPublicKey key : encKeys) {
                methods.add(createPublicKeyMethod(key));
            }
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayer(encOut, tarArchive, fileName, signKeys, signPassphrases,
                        compressionAlgorithm, hashAlgorithms, progress);
            }
        }
    }

    public void encryptCompress(TarArchive tarArchive, String fileName, OutputStream out,
                                 List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                 int compressionAlgorithm,
                                 List<Integer> hashAlgorithms, boolean armor,
                                 ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            writeInnerLayer(armored, tarArchive, fileName, signKeys, signPassphrases,
                    compressionAlgorithm, hashAlgorithms, progress);
        }
    }

    public void encryptPassword(TarArchive tarArchive, String fileName, OutputStream out,
                                  char[] password, List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                  int symmetricAlgorithm, int compressionAlgorithm,
                                  List<Integer> hashAlgorithms, boolean armor,
                                  ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            methods.add(createPBEMethod(password, symmetricAlgorithm));
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayer(encOut, tarArchive, fileName, signKeys, signPassphrases,
                        compressionAlgorithm, hashAlgorithms, progress);
            }
        }
    }

    public void encryptRaw(TarArchive tarArchive, OutputStream out,
                            List<PGPPublicKey> encKeys, int symmetricAlgorithm,
                            boolean armor,
                            ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            for (PGPPublicKey key : encKeys) {
                methods.add(createPublicKeyMethod(key));
            }
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayerRaw(encOut, tarArchive);
            }
        }
    }

    public void encryptRawPassword(TarArchive tarArchive, OutputStream out,
                                     char[] password, int symmetricAlgorithm,
                                     boolean armor,
                                     ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();
            methods.add(createPBEMethod(password, symmetricAlgorithm));
            try (OutputStream encOut = openEncrypt(symmetricAlgorithm, armored, methods)) {
                writeInnerLayerRaw(encOut, tarArchive);
            }
        }
    }

    private void writeInnerLayerRaw(OutputStream out, TarArchive tarArchive) throws Exception {
        byte[] container = TarCodec.encode(tarArchive);
        try (OutputStream litOut = new PGPLiteralDataGenerator()
                .open(out, PGPLiteralData.BINARY, "archive.tar", container.length, new Date())) {
            litOut.write(container);
        }
    }

    private OutputStream openEncrypt(int symmetricAlgorithm, OutputStream out,
                                     List<PGPKeyEncryptionMethodGenerator> methods) throws Exception {
        if (CustomAlgorithms.isCustom(symmetricAlgorithm)) {
            CustomEncryptedDataGenerator gen = new CustomEncryptedDataGenerator(symmetricAlgorithm, new SecureRandom());
            for (PGPKeyEncryptionMethodGenerator method : methods) {
                gen.addMethod(method);
            }
            return gen.open(out);
        }
        PGPEncryptedDataGenerator gen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(symmetricAlgorithm)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
        for (PGPKeyEncryptionMethodGenerator method : methods) {
            gen.addMethod(method);
        }
        return gen.open(out, new byte[CHUNK_SIZE]);
    }

    private OutputStream openCompressedData(OutputStream out, int compressionAlgorithm) throws IOException {
        if (CustomCompression.isCustom(compressionAlgorithm)) {
            return new CustomCompressedDataGenerator(compressionAlgorithm).open(out);
        }
        return new PGPCompressedDataGenerator(compressionAlgorithm).open(out);
    }

private void writeInnerLayer(OutputStream out, byte[] data, String fileName,
                                   List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                   int compressionAlgorithm,
                                   List<Integer> hashAlgorithms,
                                   ProgressCallback progress) throws Exception {
        if (compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED) {
            writeSignAndLiteral(out, data, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
        } else {
            try (OutputStream zipOut = openCompressedData(out, compressionAlgorithm)) {
                writeSignAndLiteral(zipOut, data, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
            }
        }
    }

    private void writeInnerLayer(OutputStream out, TarArchive tarArchive, String fileName,
                                   List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                   int compressionAlgorithm,
                                   List<Integer> hashAlgorithms,
                                   ProgressCallback progress) throws Exception {
        if (compressionAlgorithm == CompressionAlgorithmTags.UNCOMPRESSED) {
            writeSignAndLiteralTar(out, tarArchive, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
        } else {
            try (OutputStream zipOut = openCompressedData(out, compressionAlgorithm)) {
                writeSignAndLiteralTar(zipOut, tarArchive, fileName, signKeys, signPassphrases, hashAlgorithms, progress);
            }
        }
    }

    private PGPKeyEncryptionMethodGenerator createPublicKeyMethod(PGPPublicKey key) {
        int keyAlgo = key.getAlgorithm();
        if (keyAlgo == PublicKeyAlgorithmTags.ECDH
                || keyAlgo == PublicKeyAlgorithmTags.X25519
                || keyAlgo == PublicKeyAlgorithmTags.X448) {
            return new BcPublicKeyKeyEncryptionMethodGenerator(key).setSecureRandom(new SecureRandom());
        }
        return new JcePublicKeyKeyEncryptionMethodGenerator(key).setProvider("BC");
    }

    private PGPKeyEncryptionMethodGenerator createPBEMethod(char[] password, int symmetricAlgorithm) {
        if (CustomAlgorithms.isCustom(symmetricAlgorithm)) {
            return new CustomPBEKeyEncryptionMethodGenerator(password);
        }
        return new JcePBEKeyEncryptionMethodGenerator(password).setProvider("BC");
    }

    public void encryptCompress(byte[] data, String fileName, OutputStream out,
                                 List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                 int compressionAlgorithm,
                                 List<Integer> hashAlgorithms, boolean armor,
                                 ProgressCallback progress) throws Exception {
        try (OutputStream armored = armor ? new ArmoredOutputStream(out) : out) {
            writeInnerLayer(armored, data, fileName, signKeys, signPassphrases,
                    compressionAlgorithm, hashAlgorithms, progress);
        }
    }

    // ─── hash algorithm override per key type ─────────────────────

    private static int defaultHashForAlgo(int keyAlgorithm, int fallback) {
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed25519
                || keyAlgorithm == PublicKeyAlgorithmTags.EDDSA_LEGACY) return HashAlgorithmTags.SHA512;
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed448) return Ed448PGPContentSignerBuilder.SHAKE256;
        return fallback;
    }

    // ─── writeSignAndLiteral (byte[]) ─────────────────────────────

    private void writeSignAndLiteral(OutputStream out, byte[] data, String fileName,
                                      List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                      List<Integer> hashAlgorithms,
                                       ProgressCallback progress) throws Exception {
        long total = data.length;
        if (signKeys != null && !signKeys.isEmpty()) {
            List<PGPSignatureGenerator> sigGens = new ArrayList<>();
            for (int i = 0; i < signKeys.size(); i++) {
                char[] passphrase = signPassphrases != null && i < signPassphrases.size()
                        ? signPassphrases.get(i) : null;
                PGPPrivateKey signPrivateKey = extractPrivateKey(signKeys.get(i), passphrase);
                if (passphrase != null) {
                    cachePassphrase(signKeys.get(i).getKeyID(), passphrase);
                }
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
                PGPSignatureSubpacketGenerator unhashedGen = new PGPSignatureSubpacketGenerator();
                unhashedGen.setIssuerKeyID(false, signKeys.get(i).getKeyID());
                unhashedGen.setIssuerFingerprint(false, signPubKey);
                sigGen.setUnhashedSubpackets(unhashedGen.generate());
                boolean isLast = (i == signKeys.size() - 1);
                sigGen.generateOnePassVersion(!isLast).encode(out);
                sigGens.add(sigGen);
            }
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            try (OutputStream litOut = litGen.open(out, PGPLiteralData.BINARY,
                    fileName, total, new Date())) {
                long offset = 0;
                while (offset < total) {
                    int chunk = (int) Math.min(CHUNK_SIZE, total - offset);
                    for (PGPSignatureGenerator sigGen : sigGens) {
                        sigGen.update(data, (int) offset, chunk);
                    }
                    litOut.write(data, (int) offset, chunk);
                    offset += chunk;
                    if (progress != null)
                        progress.onProgress((int) (offset * 100 / total), "Encrypting...");
                }
            }
            for (PGPSignatureGenerator sigGen : sigGens) {
                sigGen.generate().encode(out);
            }
        } else {
            PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
            try (OutputStream dataOutputStream = litGen.open(out, PGPLiteralData.BINARY,
                    fileName, total, new Date())) {
                long offset = 0;
                while (offset < total) {
                    int chunk = (int) Math.min(CHUNK_SIZE, total - offset);
                    dataOutputStream.write(data, (int) offset, chunk);
                    offset += chunk;
                    if (progress != null)
                        progress.onProgress((int) (offset * 100 / total), "Compressing...");
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
        // Plaintext is staged in a session-encrypted temp file, never in clear on disk.
        SecureTempFile tempFile = SecureTempFile.create("pgp-nested-decrypt-", ".bin");
        try {
            return decryptNestedToFile(cipherData, tempFile, secretKeys, publicKeys,
                    publicKeyUserIdByKeyId, secretKeyUserIds, pbePasswords, progress, decodeText);
        } catch (Exception e) {
            tempFile.wipeAndDelete();
            throw e;
        }
    }

    public DecryptResult decryptNestedToFile(byte[] cipherData, SecureTempFile tempFile,
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
            List<PGPEncryptedData> openedEncData = new ArrayList<>();
            DecryptResult result = parseDecryptedStreamToFile(in, encLayers, metaBuilder, tempFile,
                    secretKeys, publicKeys, publicKeyUserIdByKeyId, secretKeyUserIds,
                    pbePasswords, openedEncData, decodeText);
            verifyEncryptionIntegrity(openedEncData);
            while (in.read() >= 0) {
                // read to EOF: enforces the armored CRC24 check on the '=XXXX' line
            }
            return result;
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
                        allIds.add(((PGPPublicKeyEncryptedData) ed).getKeyIdentifier().getKeyId());
                    }
                }
            }
        }
    }

    // ─── writeSignAndLiteral (TarArchive) ────────────────────────────

    private void writeSignAndLiteralTar(OutputStream out, TarArchive tarArchive, String fileName,
                                         List<PGPSecretKey> signKeys, List<char[]> signPassphrases,
                                         List<Integer> hashAlgorithms,
                                         ProgressCallback progress) throws Exception {
        List<PGPSignatureGenerator> sigGens = new ArrayList<>();
        if (signKeys != null && !signKeys.isEmpty()) {
            for (int i = 0; i < signKeys.size(); i++) {
                char[] passphrase = signPassphrases != null && i < signPassphrases.size()
                        ? signPassphrases.get(i) : null;
                PGPPrivateKey signPrivateKey = extractPrivateKey(signKeys.get(i), passphrase);
                if (passphrase != null) {
                    cachePassphrase(signKeys.get(i).getKeyID(), passphrase);
                }
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
                sigGen.init(PGPSignature.BINARY_DOCUMENT, extractPrivateKey(signKeys.get(i),
                        signPassphrases != null && i < signPassphrases.size() ? signPassphrases.get(i) : null));
                PGPSignatureSubpacketGenerator unhashedGen = new PGPSignatureSubpacketGenerator();
                unhashedGen.setIssuerKeyID(false, signKeys.get(i).getKeyID());
                unhashedGen.setIssuerFingerprint(false, signPubKey);
                sigGen.setUnhashedSubpackets(unhashedGen.generate());
                boolean isLast = (i == signKeys.size() - 1);
                sigGen.generateOnePassVersion(!isLast).encode(out);
                sigGens.add(sigGen);
            }
        }

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        byte[] container = TarCodec.encode(tarArchive);
        try (OutputStream litOut = litGen.open(out, PGPLiteralData.BINARY, fileName, container.length, new Date())) {
            long offset = 0;
            while (offset < container.length) {
                int chunk = (int) Math.min(CHUNK_SIZE, container.length - offset);
                for (PGPSignatureGenerator sigGen : sigGens) {
                    sigGen.update(container, (int) offset, chunk);
                }
                litOut.write(container, (int) offset, chunk);
                offset += chunk;
                if (progress != null)
                    progress.onProgress((int) (offset * 100 / container.length), "Signing...");
            }
        }
        for (PGPSignatureGenerator sigGen : sigGens) {
            sigGen.generate().encode(out);
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
        private long count;
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
                int pct = (int) Math.min(count * 100 / Math.max(total, 1), 100);
                progress.onProgress(pct, "Decrypting...");
            }
        }
    }

    // ─── parseDecryptedStream → temp file (recursive) ────────────

    private DecryptResult parseDecryptedStreamToFile(InputStream clearStream,
                                                       List<DecryptResult.EncryptionLayer> encLayers,
                                                       DecryptResult.Metadata.Builder metaBuilder,
                                                       SecureTempFile tempFile,
                                                       List<PGPSecretKey> secretKeys,
                                                       List<PGPPublicKey> publicKeys,
                                                       Map<Long, String> publicKeyUserIdByKeyId,
                                                       Map<Long, String> secretKeyUserIds,
                                                       List<char[]> pbePasswords,
                                                       List<PGPEncryptedData> openedEncData,
                                                       boolean decodeText) throws Exception {
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clearStream);
        Object message = plainFact.nextObject();

        // Nested encryption layer
        if (message instanceof PGPEncryptedDataList) {
            InputStream innerStream = decryptLayer((PGPEncryptedDataList) message, encLayers,
                    secretKeys, secretKeyUserIds, pbePasswords, openedEncData);
            return parseDecryptedStreamToFile(innerStream, encLayers, metaBuilder, tempFile,
                    secretKeys, publicKeys, publicKeyUserIdByKeyId, secretKeyUserIds,
                    pbePasswords, openedEncData, decodeText);
        }

        // Inner content
        Object firstContent = message;
        if (message instanceof PGPCompressedData) {
            PGPCompressedData compData = (PGPCompressedData) message;
            metaBuilder.compressionAlgorithm(compData.getAlgorithm());
            InputStream compStream = CustomCompression.isCustom(compData.getAlgorithm())
                    ? CustomCompression.decompress(compData.getInputStream(), compData.getAlgorithm())
                    : compData.getDataStream();
            plainFact = new JcaPGPObjectFactory(compStream);
            firstContent = null;
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

        return parseCompressedToFile(plainFact, firstContent, metaBuilder, tempFile,
                publicKeys, publicKeyUserIdByKeyId, decodeText);
    }

    private InputStream decryptLayer(PGPEncryptedDataList encList,
                                      List<DecryptResult.EncryptionLayer> encLayers,
                                      List<PGPSecretKey> secretKeys,
                                      Map<Long, String> secretKeyUserIds,
                                      List<char[]> pbePasswords,
                                      List<PGPEncryptedData> openedEncData) throws Exception {
        // Try PBE if passwords are available
        if (pbePasswords != null && !pbePasswords.isEmpty()) {
            for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
                PGPEncryptedData ed = it.next();
                if (ed instanceof PGPPBEEncryptedData) {
                    char[] password = pbePasswords.remove(0);
                    PBEDataDecryptorFactory pbeFactory = new CustomAwarePBEDataDecryptorFactory(password);
                    int symAlgo = ((PGPPBEEncryptedData) ed).getSymmetricAlgorithm(pbeFactory);
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PASSWORD, symAlgo, 0,
                            null, null, null));
                    openedEncData.add(ed);
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
                    PBEDataDecryptorFactory pbeFactory = new CustomAwarePBEDataDecryptorFactory(password);
                    int symAlgo = ((PGPPBEEncryptedData) ed).getSymmetricAlgorithm(pbeFactory);
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PASSWORD, symAlgo, 0,
                            null, null, null));
                    openedEncData.add(ed);
                    return ((PGPPBEEncryptedData) ed).getDataStream(pbeFactory);
                }
            }
        }

        // Public-key layer
        List<Long> allRecipientIds = new ArrayList<>();
        for (Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects(); it.hasNext();) {
            PGPEncryptedData ed = it.next();
            if (ed instanceof PGPPublicKeyEncryptedData) {
                allRecipientIds.add(((PGPPublicKeyEncryptedData) ed).getKeyIdentifier().getKeyId());
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

                    PGPPublicKeyEncryptedData encData = findEncDataById(encList, rid);
                    InputStream clearStream;
                    int symAlgo;
                    try {
                        PublicKeyDataDecryptorFactory decryptorFactory = new CustomAwarePublicKeyDataDecryptorFactory(
                                new JcePublicKeyDataDecryptorFactoryBuilder()
                                        .setProvider("BC").build(privateKey));
                        symAlgo = encData.getSymmetricAlgorithm(decryptorFactory);
                        clearStream = encData.getDataStream(decryptorFactory);
                    } catch (Exception e) {
                        PublicKeyDataDecryptorFactory decryptorFactory = new CustomAwarePublicKeyDataDecryptorFactory(
                                new BcPublicKeyDataDecryptorFactory(privateKey));
                        symAlgo = encData.getSymmetricAlgorithm(decryptorFactory);
                        clearStream = encData.getDataStream(decryptorFactory);
                    }
                    String uid = secretKeyUserIds != null ? secretKeyUserIds.get(encData.getKeyIdentifier().getKeyId()) : null;
                    encLayers.add(new DecryptResult.EncryptionLayer(
                            DecryptResult.EncryptionLayer.Type.PUBLIC_KEY, symAlgo,
                            sk.getPublicKey().getAlgorithm(),
                            KeyringLoader.curveName(sk.getPublicKey()),
                            encData.getKeyIdentifier().getKeyId(), allRecipientIds, uid));
                    passphraseCache.put(sk.getKeyID(), passphrase);

                    openedEncData.add(encData);
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

    // ─── Integrity verification (MDC + armored CRC24) ────────────

    private void verifyEncryptionIntegrity(List<PGPEncryptedData> openedEncData) throws Exception {
        for (int i = openedEncData.size() - 1; i >= 0; i--) {
            PGPEncryptedData ed = openedEncData.get(i);
            if (!ed.isIntegrityProtected()) continue;
            if (!ed.verify()) {
                throw new PGPException("Integrity check failed (MDC)");
            }
        }
    }

    // ─── parseCompressed → temp file ─────────────────────────────

    private DecryptResult parseCompressedToFile(JcaPGPObjectFactory plainFact,
                                                  Object firstContent,
                                                  DecryptResult.Metadata.Builder metaBuilder,
                                                  SecureTempFile tempFile,
                                                  List<PGPPublicKey> publicKeys,
                                                  Map<Long, String> publicKeyUserIdByKeyId,
                                                  boolean decodeText) throws Exception {
        Object message = firstContent != null ? firstContent : plainFact.nextObject();

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
            try (OutputStream fileOut = tempFile.openWrite()) {
                byte[] buf = new byte[CHUNK_SIZE];
                int n;
                while ((n = litStream.read(buf)) >= 0) {
                    fileOut.write(buf, 0, n);
                    totalWritten += n;
                }
            }
            byte[] rawData = totalWritten <= 50_000_000
                    ? tempFile.readAllPlaintext() : null;
            byte[] verifyData = rawData != null ? rawData : tempFile.readAllPlaintext();
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
                        pubKey != null ? KeyringLoader.curveName(pubKey) : null,
                        sigTime));
            }

            TarArchive tarArchive = null;
            CompoundMessage compound = null;
            String plainText;
            if (totalWritten > 0) {
                byte[] probe = compoundProbe(tempFile, rawData, totalWritten);
                if (probe != null && (CompoundCodec.isCompound(probe) || TarCodec.isCompound(probe))) {
                    try (InputStream decodeIn = tempFile.openRead()) {
                        if (TarCodec.isCompound(probe)) {
                            TarArchive tar = TarCodec.decode(decodeIn, (int) totalWritten, tempFile);
                            tarArchive = tar;
                            plainText = tar.getPlainText();
                        } else {
                            compound = CompoundCodec.decode(decodeIn, (int) totalWritten, tempFile);
                            plainText = compound.getPlainText();
                        }
                    }
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
                metaBuilder.signerPublicKeyAlgorithm(signers.get(0).getPublicKeyAlgorithm());
                if (signers.get(0).getCurve() != null)
                    metaBuilder.signerCurve(signers.get(0).getCurve());
                if (signers.get(0).getSignatureTime() != null)
                    metaBuilder.signatureCreationTime(signers.get(0).getSignatureTime());
                if (signers.get(0).getUserId() != null)
                    metaBuilder.signerUserId(signers.get(0).getUserId());
            }

            if (tarArchive != null) {
                return new DecryptResult(plainText, rawData, overallStatus, signers,
                        metaBuilder.build(), tarArchive, tempFile);
            } else {
                return new DecryptResult(plainText, rawData, overallStatus, signers,
                        metaBuilder.build(), compound, tempFile);
            }
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData litData = (PGPLiteralData) message;
            metaBuilder.literalFormat((char) litData.getFormat())
                       .fileName(litData.getFileName())
                       .modificationTime(litData.getModificationTime());

            // Write literal data to the session-encrypted temp file
            InputStream litStream = litData.getDataStream();
            long totalWritten;
            try (OutputStream fileOut = tempFile.openWrite()) {
                byte[] buf = new byte[CHUNK_SIZE];
                int n;
                while ((n = litStream.read(buf)) >= 0) {
                    fileOut.write(buf, 0, n);
                }
                totalWritten = tempFile.plaintextSize();
            }
            byte[] rawData = totalWritten <= 50_000_000
                    ? tempFile.readAllPlaintext() : null;

TarArchive tarArchive = null;
            CompoundMessage compound = null;
            String plainText;
            if (totalWritten > 0) {
                byte[] probe = compoundProbe(tempFile, rawData, totalWritten);
                if (probe != null && (CompoundCodec.isCompound(probe) || TarCodec.isCompound(probe))) {
                    try (InputStream decodeIn = tempFile.openRead()) {
                        if (TarCodec.isCompound(probe)) {
                            TarArchive tar = TarCodec.decode(decodeIn, (int) totalWritten, tempFile);
                            tarArchive = tar;
                            plainText = tar.getPlainText();
                        } else {
                            compound = CompoundCodec.decode(decodeIn, (int) totalWritten, tempFile);
                            plainText = compound.getPlainText();
                        }
                    }
                } else if (rawData != null && decodeText) {
                    plainText = new String(rawData, StandardCharsets.UTF_8);
                } else {
                    plainText = "";
                }
            } else {
                plainText = "";
            }

            if (tarArchive != null) {
                return new DecryptResult(plainText, rawData,
                        DecryptResult.VerificationStatus.NOT_SIGNED, null, metaBuilder.build(), tarArchive, tempFile);
            } else {
                return new DecryptResult(plainText, rawData,
                        DecryptResult.VerificationStatus.NOT_SIGNED, null, metaBuilder.build(), compound, tempFile);
            }
        }

        throw new PGPException("Unexpected packet: " + (message != null ? message.getClass().getName() : "null"));
    }

    /**
     * First up-to-4 bytes of the decrypted literal data, from the in-memory copy
     * when present, otherwise via a slice read (large literals stay off-heap).
     * Returns null when fewer than 4 bytes are available or the slice fails.
     */
    private static byte[] compoundProbe(SecureTempFile tempFile, byte[] rawData, long totalWritten) {
        if (rawData != null) {
            return rawData.length >= 4 ? rawData : null;
        }
        if (totalWritten < 4) return null;
        try {
            return tempFile.readSlice(0, 4);
        } catch (IOException e) {
            return null;
        }
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
                    && ((PGPPublicKeyEncryptedData) ed).getKeyIdentifier().getKeyId() == keyId) {
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

    public void removePassphrase(long keyId) {
        passphraseCache.remove(keyId);
    }

    public static boolean isWrongPassphrase(Throwable t) {
        return wrongPassphraseKeyId(t) != null;
    }

    public static Long wrongPassphraseKeyId(Throwable t) {
        Throwable c = t;
        while (c != null) {
            if (c instanceof PassphraseRequiredException) {
                return ((PassphraseRequiredException) c).getKeyId();
            }
            c = c.getCause();
        }
        return null;
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
                if (isChecksumMismatch(e2)) {
                    throw new PassphraseRequiredException(key.getKeyID(), firstUserId(key), e2);
                }
                throw new PGPException("failed to extract private key", e2);
            }
        }
    }

    private static boolean isChecksumMismatch(Throwable t) {
        Throwable c = t;
        while (c != null) {
            String m = c.getMessage();
            if (m != null && m.contains("checksum mismatch")) return true;
            c = c.getCause();
        }
        return false;
    }

    private static String firstUserId(PGPSecretKey key) {
        Iterator<String> uids = key.getUserIDs();
        return uids.hasNext() ? uids.next() : null;
    }
}
