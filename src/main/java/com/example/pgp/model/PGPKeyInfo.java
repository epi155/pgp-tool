package com.example.pgp.model;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PGPKeyInfo {
    private final long keyId;
    private final String fingerprint;
    private final String algorithm;
    private final int bitLength;
    private final Date creationTime;
    private final boolean isMasterKey;
    private final boolean canSign;
    private final boolean canEncrypt;
    private final List<String> userIds;
    private final Object bcKey;
    private final List<PGPKeyInfo> subKeys;

    public PGPKeyInfo(long keyId, String fingerprint, String algorithm, int bitLength,
                      Date creationTime, boolean isMasterKey, boolean canSign,
                      boolean canEncrypt, List<String> userIds, Object bcKey) {
        this.keyId = keyId;
        this.fingerprint = fingerprint;
        this.algorithm = algorithm;
        this.bitLength = bitLength;
        this.creationTime = creationTime;
        this.isMasterKey = isMasterKey;
        this.canSign = canSign;
        this.canEncrypt = canEncrypt;
        this.userIds = userIds != null ? userIds : new ArrayList<>();
        this.bcKey = bcKey;
        this.subKeys = new ArrayList<>();
    }

    public long getKeyId() { return keyId; }
    public String getKeyIdHex() { return String.format("0x%08X", keyId); }
    public String getFingerprint() { return fingerprint; }
    public String getAlgorithm() { return algorithm; }
    public int getBitLength() { return bitLength; }
    public Date getCreationTime() { return creationTime; }
    public boolean isMasterKey() { return isMasterKey; }
    public boolean canSign() { return canSign; }
    public boolean canEncrypt() { return canEncrypt; }
    public String getUserId() { return userIds.isEmpty() ? null : userIds.get(0); }
    public List<String> getUserIds() { return userIds; }
    public List<PGPKeyInfo> getSubKeys() { return subKeys; }

    @SuppressWarnings("unchecked")
    public <T> T getBcKey(Class<T> type) { return (T) bcKey; }

    @Override
    public String toString() {
        String ts = new SimpleDateFormat("yyyy-MM-dd").format(creationTime);
        StringBuilder sb = new StringBuilder();
        sb.append(algorithm).append(" ").append(bitLength).append("b");
        sb.append(" ").append(getKeyIdHex());
        if (isMasterKey) {
            sb.append(" [");
            if (canSign) sb.append("S");
            if (canEncrypt) sb.append("E");
            sb.append("]");
            for (String uid : userIds) {
                sb.append(" ").append(uid);
            }
        } else {
            sb.append(" [");
            if (canSign) sb.append("S");
            if (canEncrypt) sb.append("E");
            sb.append("]");
        }
        return sb.toString();
    }
}
