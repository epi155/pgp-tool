package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class CustomPBEKeyEncryptionMethodGenerator extends PBEKeyEncryptionMethodGenerator {

    public CustomPBEKeyEncryptionMethodGenerator(char[] passPhrase) {
        this(passPhrase, sha1Calculator());
    }

    public CustomPBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator) {
        super(passPhrase, s2kDigestCalculator);
        setSecureRandom(new SecureRandom());
    }

    private static PGPDigestCalculator sha1Calculator() {
        try {
            return new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        } catch (PGPException e) {
            throw new IllegalStateException("Exception creating SHA-1 digest calculator", e);
        }
    }

    @Override
    public byte[] getKey(int keyAlgorithm) throws PGPException {
        return super.getKey(CustomAlgorithms.proxyTag(keyAlgorithm));
    }

    @Override
    protected byte[] encryptSessionInfo(int keyAlgorithm, byte[] key, byte[] secKeyData) throws PGPException {
        String name = CustomAlgorithms.eskWrapName(keyAlgorithm);
            String transformation = CustomAlgorithms.isChaCha20(keyAlgorithm)
                    ? name
                    : name + "/CFB/NoPadding";
        try {
            Cipher c = Cipher.getInstance(transformation, "BC");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, name), CustomAlgorithms.makeIv(keyAlgorithm));
            return c.doFinal(secKeyData);
        } catch (Exception e) {
            throw new PGPException("Exception encrypting session info", e);
        }
    }

    @Override
    protected byte[] getEskAndTag(int keyAlgorithm, int aeadAlgorithm, byte[] key, byte[] sessionKey, byte[] iv, byte[] kek) throws PGPException {
        throw new PGPException("AEAD not supported for custom algorithms");
    }

    @Override
    protected byte[] generateV6KEK(int keyAlgorithm, byte[] key, byte[] esk) throws PGPException {
        throw new PGPException("AEAD not supported for custom algorithms");
    }
}
