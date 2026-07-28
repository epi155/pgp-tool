package com.example.pgp.service;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class Ed448PGPContentSignerBuilder implements PGPContentSignerBuilder {

    public static final int SHAKE256 = 27;

    private final int hashAlgorithm;
    private final SecureRandom random;

    public Ed448PGPContentSignerBuilder(int hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
        this.random = new SecureRandom();
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
                return SHAKE256;
            }
        };
    }

    @Override
    public PGPContentSigner build(final int signatureType, final PGPPrivateKey privateKey) throws PGPException {
        try {
            PrivateKey jcaPrivateKey = new JcaPGPKeyConverter().getPrivateKey(privateKey);
            final Signature signature = Signature.getInstance("Ed448", "BC");
            signature.initSign(jcaPrivateKey, random);

            final PGPDigestCalculator edDigestCalculator = shake256DigestCalculator();
            final PGPDigestCalculator digestCalculator = shake256DigestCalculator();

            return new PGPContentSigner() {
                @Override
                public int getType() {
                    return signatureType;
                }

                @Override
                public OutputStream getOutputStream() {
                    return new TeeOutputStream(
                            edDigestCalculator.getOutputStream(),
                            digestCalculator.getOutputStream());
                }

                @Override
                public byte[] getSignature() {
                    try {
                        signature.update(edDigestCalculator.getDigest());
                        return signature.sign();
                    } catch (SignatureException e) {
                        throw new PGPRuntimeOperationException("Unable to create signature: " + e.getMessage(), e);
                    }
                }

                @Override
                public byte[] getDigest() {
                    return digestCalculator.getDigest();
                }

                @Override
                public int getHashAlgorithm() {
                    return hashAlgorithm;
                }

                @Override
                public int getKeyAlgorithm() {
                    return PublicKeyAlgorithmTags.Ed448;
                }

                @Override
                public long getKeyID() {
                    return privateKey.getKeyID();
                }
            };
        } catch (GeneralSecurityException e) {
            throw new PGPException("Cannot build Ed448 signer", e);
        }
    }
}
