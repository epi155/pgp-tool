package com.example.pgp.service;

import com.example.pgp.model.KeyBundle;
import com.example.pgp.model.PGPKeyInfo;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class KeyringLoader {
    private KeyringLoader() {}

    public static KeyBundle loadPublicKeys(File file) throws IOException, PGPException {
        byte[] rawBytes = readAllBytes(file);
        List<PGPPublicKeyRing> rings = readPublicKeyRings(rawBytes);
        List<PGPKeyInfo> keys = new ArrayList<>();
        for (PGPPublicKeyRing ring : rings) {
            keys.addAll(extractPublicKeyInfos(ring));
        }
        return new KeyBundle(keys, file.getAbsolutePath());
    }

    public static KeyBundle loadSecretKeys(File file) throws IOException, PGPException {
        byte[] rawBytes = readAllBytes(file);
        List<PGPSecretKeyRing> rings = readSecretKeyRings(rawBytes);
        List<PGPKeyInfo> keys = new ArrayList<>();
        for (PGPSecretKeyRing ring : rings) {
            keys.addAll(extractSecretKeyInfos(ring));
        }
        return new KeyBundle(keys, file.getAbsolutePath());
    }

    private static byte[] readAllBytes(File file) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(file)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static boolean isArmored(byte[] raw) {
        String s = new String(raw, 0, Math.min(raw.length, 50), StandardCharsets.US_ASCII).trim();
        return s.startsWith("-----BEGIN PGP");
    }

    private static InputStream decode(byte[] raw) throws IOException {
        if (isArmored(raw)) {
            return new ArmoredInputStream(new ByteArrayInputStream(raw));
        }
        return new ByteArrayInputStream(raw);
    }

    private static List<PGPPublicKeyRing> readPublicKeyRings(byte[] raw) throws PGPException {
        List<PGPPublicKeyRing> rings = new ArrayList<>();
        try {
            InputStream in = decode(raw);
            PGPPublicKeyRingCollection col = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> it = col.getKeyRings();
            while (it.hasNext()) rings.add(it.next());
            if (!rings.isEmpty()) return rings;
        } catch (Exception ignored) {}

        try (InputStream in = new ByteArrayInputStream(raw)) {
            InputStream keyIn = isArmored(raw) ? new ArmoredInputStream(in) : in;
            rings.add(new PGPPublicKeyRing(keyIn, new JcaKeyFingerprintCalculator()));
        } catch (Exception e2) {
            throw new PGPException("No valid PGP public key found in file", e2);
        }
        return rings;
    }

    private static List<PGPSecretKeyRing> readSecretKeyRings(byte[] raw) throws PGPException {
        List<PGPSecretKeyRing> rings = new ArrayList<>();
        try {
            InputStream in = decode(raw);
            PGPSecretKeyRingCollection col = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
            Iterator<PGPSecretKeyRing> it = col.getKeyRings();
            while (it.hasNext()) rings.add(it.next());
            if (!rings.isEmpty()) return rings;
        } catch (Exception ignored) {}

        try (InputStream in = new ByteArrayInputStream(raw)) {
            InputStream keyIn = isArmored(raw) ? new ArmoredInputStream(in) : in;
            rings.add(new PGPSecretKeyRing(keyIn, new JcaKeyFingerprintCalculator()));
        } catch (Exception e2) {
            throw new PGPException("No valid PGP secret key found in file", e2);
        }
        return rings;
    }

    public static List<PGPKeyInfo> extractKeyInfos(PGPSecretKeyRing secretKeyRing) {
        return extractSecretKeyInfos(secretKeyRing);
    }

    public static List<PGPKeyInfo> extractKeyInfos(PGPPublicKeyRing publicKeyRing) {
        return extractPublicKeyInfos(publicKeyRing);
    }

    private static List<PGPKeyInfo> extractPublicKeyInfos(PGPPublicKeyRing ring) {
        List<PGPKeyInfo> keys = new ArrayList<>();
        PGPPublicKey masterKey = ring.getPublicKey();
        PGPKeyInfo masterInfo = createKeyInfo(masterKey, true);
        keys.add(masterInfo);
        Iterator<PGPPublicKey> it = ring.getPublicKeys();
        while (it.hasNext()) {
            PGPPublicKey key = it.next();
            if (!key.isMasterKey()) {
                masterInfo.getSubKeys().add(createKeyInfo(key, false));
            }
        }
        return keys;
    }

    private static List<PGPKeyInfo> extractSecretKeyInfos(PGPSecretKeyRing ring) {
        List<PGPKeyInfo> keys = new ArrayList<>();
        PGPSecretKey masterKey = ring.getSecretKey();
        PGPKeyInfo masterInfo = createKeyInfo(masterKey, true);
        keys.add(masterInfo);
        Iterator<PGPSecretKey> it = ring.getSecretKeys();
        while (it.hasNext()) {
            PGPSecretKey key = it.next();
            if (!key.isMasterKey()) {
                masterInfo.getSubKeys().add(createKeyInfo(key, false));
            }
        }
        return keys;
    }

    private static PGPKeyInfo createKeyInfo(PGPPublicKey key, boolean isMaster) {
        long keyId = key.getKeyID();
        String fp = fingerprintHex(key.getFingerprint());
        String algorithm = algorithmName(key.getAlgorithm());
        int bitLen = key.getBitStrength();
        if (bitLen == 0) bitLen = bitLenFor(key.getAlgorithm());
        Date creation = key.getCreationTime();
        boolean canSign = hasSignCapability(key);
        boolean canEncrypt = hasEncryptCapability(key);
        List<String> userIds = new ArrayList<>();
        if (isMaster) {
            Iterator<String> uids = key.getUserIDs();
            while (uids.hasNext()) userIds.add(uids.next());
        }
        return new PGPKeyInfo(keyId, fp, algorithm, bitLen, creation, isMaster,
                canSign, canEncrypt, userIds, key);
    }

    private static PGPKeyInfo createKeyInfo(PGPSecretKey key, boolean isMaster) {
        PGPPublicKey pubKey = key.getPublicKey();
        long keyId = key.getKeyID();
        String fp = fingerprintHex(pubKey.getFingerprint());
        String algorithm = algorithmName(pubKey.getAlgorithm());
        int bitLen = pubKey.getBitStrength();
        if (bitLen == 0) bitLen = bitLenFor(pubKey.getAlgorithm());
        Date creation = pubKey.getCreationTime();
        boolean canSign = hasSignCapability(pubKey);
        boolean canEncrypt = hasEncryptCapability(pubKey);
        List<String> userIds = new ArrayList<>();
        if (isMaster) {
            Iterator<String> uids = key.getUserIDs();
            while (uids.hasNext()) userIds.add(uids.next());
        }
        return new PGPKeyInfo(keyId, fp, algorithm, bitLen, creation, isMaster,
                canSign, canEncrypt, userIds, key);
    }

    private static int bitLenFor(int algo) {
        switch (algo) {
            case PublicKeyAlgorithmTags.Ed25519:
            case PublicKeyAlgorithmTags.EDDSA:
            case PublicKeyAlgorithmTags.X25519:
            case PublicKeyAlgorithmTags.ECDH:
                return 256;
            case PublicKeyAlgorithmTags.Ed448:
            case PublicKeyAlgorithmTags.X448:
                return 448;
            default:
                return 0;
        }
    }

    private static String algorithmName(int algo) {
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

    private static boolean hasSignCapability(PGPPublicKey key) {
        int algo = key.getAlgorithm();
        if (algo == PublicKeyAlgorithmTags.ECDH ||
            algo == PublicKeyAlgorithmTags.X25519 ||
            algo == PublicKeyAlgorithmTags.X448) return false;
        int flags = extractKeyFlags(key);
        if (flags != 0) {
            return (flags & KeyFlags.SIGN_DATA) != 0;
        }
        return key.isMasterKey() && (
                algo == PublicKeyAlgorithmTags.RSA_GENERAL ||
                algo == PublicKeyAlgorithmTags.RSA_SIGN ||
                algo == PublicKeyAlgorithmTags.DSA ||
                algo == PublicKeyAlgorithmTags.ECDSA ||
                algo == PublicKeyAlgorithmTags.EDDSA ||
                algo == PublicKeyAlgorithmTags.Ed25519 ||
                algo == PublicKeyAlgorithmTags.Ed448);
    }

    private static boolean hasEncryptCapability(PGPPublicKey key) {
        int algo = key.getAlgorithm();
        if (algo == PublicKeyAlgorithmTags.ECDSA ||
            algo == PublicKeyAlgorithmTags.DSA ||
            algo == PublicKeyAlgorithmTags.EDDSA ||
            algo == PublicKeyAlgorithmTags.Ed25519 ||
            algo == PublicKeyAlgorithmTags.Ed448) return false;
        int flags = extractKeyFlags(key);
        if (flags != 0) {
            return (flags & (KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE)) != 0;
        }
        return key.isEncryptionKey();
    }

    private static int extractKeyFlags(PGPPublicKey key) {
        int flags = 0;
        if (key.isMasterKey()) {
            Iterator<String> uids = key.getUserIDs();
            while (uids.hasNext()) {
                Iterator<PGPSignature> sigs = key.getSignaturesForID(uids.next());
                while (sigs.hasNext()) {
                    PGPSignature sig = sigs.next();
                    int t = sig.getSignatureType();
                    if (t == PGPSignature.DEFAULT_CERTIFICATION ||
                        t == PGPSignature.NO_CERTIFICATION ||
                        t == PGPSignature.CASUAL_CERTIFICATION ||
                        t == PGPSignature.POSITIVE_CERTIFICATION) {
                        PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
                        if (sv != null) flags |= sv.getKeyFlags();
                    }
                }
            }
            Iterator<PGPSignature> dirSigs = key.getSignaturesOfType(PGPSignature.DIRECT_KEY);
            while (dirSigs.hasNext()) {
                PGPSignatureSubpacketVector sv = dirSigs.next().getHashedSubPackets();
                if (sv != null) flags |= sv.getKeyFlags();
            }
        } else {
            Iterator<PGPSignature> sigs = key.getSignatures();
            while (sigs.hasNext()) {
                PGPSignature sig = sigs.next();
                if (sig.getSignatureType() == PGPSignature.SUBKEY_BINDING) {
                    PGPSignatureSubpacketVector sv = sig.getHashedSubPackets();
                    if (sv != null) flags |= sv.getKeyFlags();
                }
            }
        }
        return flags;
    }

    private static String fingerprintHex(byte[] fp) {
        StringBuilder sb = new StringBuilder();
        for (byte b : fp) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
