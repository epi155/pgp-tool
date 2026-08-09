package io.github.epi155.pgp.model;

import java.util.ArrayList;
import java.util.List;

public class KeyConfig {
    private String userId;
    private KeySpec masterKey;
    private List<KeySpec> subKeys = new ArrayList<>();

    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }

    public KeySpec getMasterKey() { return masterKey; }
    public void setMasterKey(KeySpec masterKey) { this.masterKey = masterKey; }

    public List<KeySpec> getSubKeys() { return subKeys; }
    public void setSubKeys(List<KeySpec> subKeys) { this.subKeys = subKeys; }

    public static class KeySpec {
        public enum Algorithm { RSA, ECDSA, EDDSA, ED448, ECDH, XDH, X448 }

        private Algorithm algorithm;
        private int rsaSize;
        private String ecCurve;
        private boolean canCertify;
        private boolean canSign;
        private boolean canEncrypt;
        private boolean canAuthenticate;
        private long expirationSeconds;

        public KeySpec() {}

        public KeySpec(Algorithm algorithm, int rsaSize, String ecCurve) {
            this.algorithm = algorithm;
            this.rsaSize = rsaSize;
            this.ecCurve = ecCurve;
        }

        public Algorithm getAlgorithm() { return algorithm; }
        public void setAlgorithm(Algorithm algorithm) { this.algorithm = algorithm; }

        public int getRsaSize() { return rsaSize; }
        public void setRsaSize(int rsaSize) { this.rsaSize = rsaSize; }

        public String getEcCurve() { return ecCurve; }
        public void setEcCurve(String ecCurve) { this.ecCurve = ecCurve; }

        public boolean isCanCertify() { return canCertify; }
        public void setCanCertify(boolean canCertify) { this.canCertify = canCertify; }

        public boolean isCanSign() { return canSign; }
        public void setCanSign(boolean canSign) { this.canSign = canSign; }

        public boolean isCanEncrypt() { return canEncrypt; }
        public void setCanEncrypt(boolean canEncrypt) { this.canEncrypt = canEncrypt; }

        public boolean isCanAuthenticate() { return canAuthenticate; }
        public void setCanAuthenticate(boolean canAuthenticate) { this.canAuthenticate = canAuthenticate; }

        public long getExpirationSeconds() { return expirationSeconds; }
        public void setExpirationSeconds(long expirationSeconds) { this.expirationSeconds = expirationSeconds; }
    }
}
