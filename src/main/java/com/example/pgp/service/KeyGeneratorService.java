package com.example.pgp.service;

import com.example.pgp.model.GeneratedKey;
import com.example.pgp.model.KeyConfig;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class KeyGeneratorService {
    private KeyGeneratorService() {}

    public static GeneratedKey generate(KeyConfig config) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        int masterAlgoTag = algoTag(config.getMasterKey());
        KeyPair masterJavaPair = generateKeyPair(config.getMasterKey());
        JcaPGPKeyPair masterKeyPair = new JcaPGPKeyPair(masterAlgoTag, masterJavaPair, new Date());

        String userId = config.getUserId();

        PGPSignatureSubpacketGenerator hashedGen = new PGPSignatureSubpacketGenerator();
        int masterFlags = 0;
        if (config.getMasterKey().isCanCertify()) masterFlags |= KeyFlags.CERTIFY_OTHER;
        if (config.getMasterKey().isCanSign()) masterFlags |= KeyFlags.SIGN_DATA;
        if (config.getMasterKey().isCanEncrypt()) masterFlags |= KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
        if (masterFlags == 0) masterFlags = KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA;
        hashedGen.setKeyFlags(false, masterFlags);
        long masterExp = config.getMasterKey().getExpirationSeconds();
        if (masterExp > 0) hashedGen.setKeyExpirationTime(false, masterExp);
        hashedGen.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128});
        hashedGen.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA256});
        hashedGen.setPreferredCompressionAlgorithms(false, new int[]{
                CompressionAlgorithmTags.ZLIB, CompressionAlgorithmTags.BZIP2,
                CompressionAlgorithmTags.ZIP});

        JcaPGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                masterKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                .setProvider("BC");

        PBESecretKeyEncryptor emptyEncryptor = new PBESecretKeyEncryptor(
                SymmetricKeyAlgorithmTags.NULL, (PGPDigestCalculator) null,
                new SecureRandom(), new char[0]) {
            @Override
            public byte[] encryptKeyData(byte[] keyData, byte[] iv,
                                          int alg, int s2kUsage) {
                return keyData;
            }
            @Override
            public byte[] getCipherIV() {
                return null;
            }
        };

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider("BC").build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator ringGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                masterKeyPair,
                userId,
                sha1Calc,
                hashedGen.generate(),
                null,
                signerBuilder,
                emptyEncryptor);

        List<PGPKeyPair> subKeyPairs = new ArrayList<>();
        for (KeyConfig.KeySpec spec : config.getSubKeys()) {
            int subAlgoTag = algoTag(spec);
            KeyPair subJavaPair = generateKeyPair(spec);
            JcaPGPKeyPair subKeyPair = new JcaPGPKeyPair(subAlgoTag, subJavaPair, new Date());

            PGPSignatureSubpacketGenerator subHashed = new PGPSignatureSubpacketGenerator();
            int subFlags = 0;
            if (spec.isCanSign()) subFlags |= KeyFlags.SIGN_DATA;
            if (spec.isCanEncrypt()) subFlags |= KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
            if (subFlags == 0) subFlags = KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE;
            subHashed.setKeyFlags(false, subFlags);
            long subExp = spec.getExpirationSeconds();
            if (subExp > 0) subHashed.setKeyExpirationTime(false, subExp);

            ringGen.addSubKey(subKeyPair, subHashed.generate(), null);
            subKeyPairs.add(subKeyPair);
        }

        PGPPublicKeyRing pubRing = ringGen.generatePublicKeyRing();
        PGPSecretKeyRing secRing = ringGen.generateSecretKeyRing();

        return new GeneratedKey(pubRing, secRing, masterKeyPair, subKeyPairs);
    }

    private static int algoTag(KeyConfig.KeySpec spec) {
        switch (spec.getAlgorithm()) {
            case RSA: return PublicKeyAlgorithmTags.RSA_GENERAL;
            case ECDSA: return PublicKeyAlgorithmTags.ECDSA;
            case EDDSA: return PublicKeyAlgorithmTags.EDDSA;
            case ED448: return PublicKeyAlgorithmTags.Ed448;
            case ECDH: return PublicKeyAlgorithmTags.ECDH;
            case XDH: return PublicKeyAlgorithmTags.X25519;
            case X448: return PublicKeyAlgorithmTags.X448;
        }
        throw new IllegalArgumentException("Unknown algorithm: " + spec.getAlgorithm());
    }

    private static KeyPair generateKeyPair(KeyConfig.KeySpec spec) throws Exception {
        switch (spec.getAlgorithm()) {
            case RSA: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
                kpg.initialize(spec.getRsaSize(), new SecureRandom());
                return kpg.generateKeyPair();
            }
            case ECDSA:
            case ECDH: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.ECDSA ? "ECDSA" : "ECDH",
                        "BC");
                kpg.initialize(new ECGenParameterSpec(spec.getEcCurve()), new SecureRandom());
                return kpg.generateKeyPair();
            }
            case EDDSA: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
                return kpg.generateKeyPair();
            }
            case ED448: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448", "BC");
                return kpg.generateKeyPair();
            }
            case XDH: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519", "BC");
                return kpg.generateKeyPair();
            }
            case X448: {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("X448", "BC");
                return kpg.generateKeyPair();
            }
        }
        throw new IllegalArgumentException("Unknown algorithm: " + spec.getAlgorithm());
    }

    public static PGPSecretKeyRing reEncrypt(PGPSecretKeyRing oldRing, char[] newPassphrase) throws Exception {
        PBESecretKeyDecryptor oldDecryptor = new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()).build(new char[0]);

        JcePBESecretKeyEncryptorBuilder encBuilder = new JcePBESecretKeyEncryptorBuilder(
                SymmetricKeyAlgorithmTags.AES_256).setProvider("BC");
        PBESecretKeyEncryptor newEncryptor = encBuilder.build(newPassphrase);

        return PGPSecretKeyRing.copyWithNewPassword(oldRing, oldDecryptor, newEncryptor);
    }
}
