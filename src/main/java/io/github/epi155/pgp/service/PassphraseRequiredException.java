package io.github.epi155.pgp.service;

import org.bouncycastle.openpgp.PGPException;

public class PassphraseRequiredException extends PGPException {
    private final long keyId;
    private final String userId;

    public PassphraseRequiredException(long keyId, String userId, Exception cause) {
        super(buildMessage(keyId, userId), cause);
        this.keyId = keyId;
        this.userId = userId;
    }

    private static String buildMessage(long keyId, String userId) {
        StringBuilder sb = new StringBuilder("password required for secret key ")
                .append(String.format("0x%08X", keyId));
        if (userId != null) {
            sb.append(" (user-id: ").append(userId).append(")");
        }
        return sb.toString();
    }

    public long getKeyId() {
        return keyId;
    }

    public String getUserId() {
        return userId;
    }
}
