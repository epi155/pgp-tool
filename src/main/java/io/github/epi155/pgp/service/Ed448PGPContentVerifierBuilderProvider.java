package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class Ed448PGPContentVerifierBuilderProvider implements PGPContentVerifierBuilderProvider {

    private final JcaPGPContentVerifierBuilderProvider fallback;

    public Ed448PGPContentVerifierBuilderProvider() {
        this.fallback = new JcaPGPContentVerifierBuilderProvider().setProvider("BC");
    }

    @Override
    public PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm) throws PGPException {
        if (keyAlgorithm == PublicKeyAlgorithmTags.Ed448 && hashAlgorithm == Ed448PGPContentSignerBuilder.SHAKE256) {
            return new Ed448VerifierBuilder(keyAlgorithm, hashAlgorithm);
        }
        return fallback.get(keyAlgorithm, hashAlgorithm);
    }

    private static PGPDigestCalculator shake256DigestCalculator() {
        return new PGPDigestCalculator() {
            private final SHAKEDigest digest = new SHAKEDigest(256);

            @Override
            public OutputStream getOutputStream() {
                return new OutputStream() {
                    @Override
                    public void write(int b) {
                        digest.update((byte) b);
                    }
                    @Override
                    public void write(byte[] b, int off, int len) {
                        digest.update(b, off, len);
                    }
                };
            }

            @Override
            public byte[] getDigest() {
                byte[] out = new byte[digest.getDigestSize()];
                digest.doFinal(out, 0);
                return out;
            }

            @Override
            public void reset() {
                digest.reset();
            }

            @Override
            public int getAlgorithm() {
                return Ed448PGPContentSignerBuilder.SHAKE256;
            }
        };
    }

    private static class Ed448VerifierBuilder implements PGPContentVerifierBuilder {
        private final int keyAlgorithm;
        private final int hashAlgorithm;

        Ed448VerifierBuilder(int keyAlgorithm, int hashAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            this.hashAlgorithm = hashAlgorithm;
        }

        @Override
        public PGPContentVerifier build(final PGPPublicKey publicKey) throws PGPException {
            try {
                PublicKey jcaPublicKey = new JcaPGPKeyConverter().getPublicKey(publicKey);
                final Signature signature = Signature.getInstance("Ed448", "BC");
                signature.initVerify(jcaPublicKey);

                final PGPDigestCalculator digestCalculator = shake256DigestCalculator();

                return new PGPContentVerifier() {
                    @Override
                    public OutputStream getOutputStream() {
                        return digestCalculator.getOutputStream();
                    }

                    @Override
                    public boolean verify(byte[] signatureBytes) {
                        try {
                            signature.update(digestCalculator.getDigest());
                            return signature.verify(signatureBytes);
                        } catch (SignatureException e) {
                            throw new PGPRuntimeOperationException(
                                    "unable to verify signature: " + e.getMessage(), e);
                        }
                    }

                    @Override
                    public int getHashAlgorithm() {
                        return hashAlgorithm;
                    }

                    @Override
                    public int getKeyAlgorithm() {
                        return keyAlgorithm;
                    }

                    @Override
                    public long getKeyID() {
                        return publicKey.getKeyID();
                    }
                };
            } catch (GeneralSecurityException e) {
                throw new PGPException("cannot build Ed448 verifier", e);
            }
        }
    }
}
