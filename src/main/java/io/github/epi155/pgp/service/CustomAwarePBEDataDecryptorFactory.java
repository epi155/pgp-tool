package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CustomAwarePBEDataDecryptorFactory extends PBEDataDecryptorFactory {

    private final PBEDataDecryptorFactory delegate;

    public CustomAwarePBEDataDecryptorFactory(char[] passPhrase) throws PGPException {
        super(passPhrase, new JcaPGPDigestCalculatorProviderBuilder().build());
        this.delegate = new JcePBEDataDecryptorFactoryBuilder().setProvider("BC").build(passPhrase);
    }

    public CustomAwarePBEDataDecryptorFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider) {
        super(passPhrase, calculatorProvider);
        this.delegate = new JcePBEDataDecryptorFactoryBuilder().setProvider("BC").build(passPhrase);
    }

    @Override
    public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k) throws PGPException {
        if (CustomAlgorithms.isCustom(keyAlgorithm)) {
            return delegate.makeKeyFromPassPhrase(CustomAlgorithms.proxyTag(keyAlgorithm), s2k);
        }
        return delegate.makeKeyFromPassPhrase(keyAlgorithm, s2k);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData) throws PGPException {
        if (CustomAlgorithms.isCustom(keyAlgorithm)) {
            if (secKeyData == null || secKeyData.length <= 0) {
                byte[] data = new byte[key.length + 1];
                data[0] = (byte) keyAlgorithm;
                System.arraycopy(key, 0, data, 1, key.length);
                return data;
            }
            String name = CustomAlgorithms.jceCipherName(keyAlgorithm);
            String transformation = CustomAlgorithms.isChaCha20(keyAlgorithm)
                    ? name
                    : name + "/CFB/NoPadding";
            try {
                Cipher c = Cipher.getInstance(transformation, "BC");
                c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, name), CustomAlgorithms.makeIv(keyAlgorithm));
                return c.doFinal(secKeyData);
            } catch (Exception e) {
                throw new PGPException("Exception recovering session info", e);
            }
        }
        return delegate.recoverSessionData(keyAlgorithm, key, secKeyData);
    }

    @Override
    public byte[] recoverAEADEncryptedSessionData(SymmetricKeyEncSessionPacket secKeyData, byte[] iv) throws PGPException {
        return delegate.recoverAEADEncryptedSessionData(secKeyData, iv);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key) throws PGPException {
        if (CustomAlgorithms.isCustom(encAlgorithm)) {
            return CustomPGPDataEncryptorBuilder.createDataDecryptor(encAlgorithm, withIntegrityPacket, key);
        }
        return delegate.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket secKeyData, PGPSessionKey sessionKey) throws PGPException {
        if (CustomAlgorithms.isAead(sessionKey.getAlgorithm())) {
            return new CustomAeadEncryptor(sessionKey.getAlgorithm(), sessionKey.getKey(), secKeyData.getIV(), secKeyData.getChunkSize());
        }
        return delegate.createDataDecryptor(secKeyData, sessionKey);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket secKeyData, PGPSessionKey sessionKey) throws PGPException {
        return delegate.createDataDecryptor(secKeyData, sessionKey);
    }
}
