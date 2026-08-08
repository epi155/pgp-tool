package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;

public class CustomAwarePublicKeyDataDecryptorFactory implements PublicKeyDataDecryptorFactory {

    private final PublicKeyDataDecryptorFactory delegate;

    public CustomAwarePublicKeyDataDecryptorFactory(PublicKeyDataDecryptorFactory delegate) {
        this.delegate = delegate;
    }

    @Override
    public byte[] recoverSessionData(PublicKeyEncSessionPacket keyData, InputStreamPacket data) throws PGPException {
        return delegate.recoverSessionData(keyData, data);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
        return delegate.recoverSessionData(keyAlgorithm, secKeyData);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int keyLen) throws PGPException {
        return delegate.recoverSessionData(keyAlgorithm, secKeyData, keyLen);
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
