package io.github.epi155.pgp.service;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.TeeOutputStream;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class CustomEncryptedDataGenerator {

    private static final int CHUNK_SIZE = 65536;

    private final int defAlgorithm;
    private final CustomPGPDataEncryptorBuilder builder;
    private final SecureRandom rand;
    private final List<PGPKeyEncryptionMethodGenerator> methods = new ArrayList<>();

    private BCPGOutputStream pOut;
    private OutputStream cOut;
    private OutputStream genOut;
    private PGPDigestCalculator digestCalc;

    public CustomEncryptedDataGenerator(int algorithm, SecureRandom random) {
        this.defAlgorithm = algorithm;
        this.builder = new CustomPGPDataEncryptorBuilder(algorithm, random);
        this.builder.setWithIntegrityPacket(true);
        this.rand = random != null ? random : new SecureRandom();
    }

    public void addMethod(PGPKeyEncryptionMethodGenerator method) {
        methods.add(method);
    }

    public OutputStream open(OutputStream out) throws IOException, PGPException {
        if (pOut != null) {
            throw new IllegalStateException("generator already in open state");
        }
        if (methods.isEmpty()) {
            throw new IllegalStateException("no encryption methods specified");
        }
        pOut = new BCPGOutputStream(out);

        byte[] sessionKey = CustomAlgorithms.makeRandomKey(defAlgorithm, rand);
        PGPDataEncryptor dataEncryptor = builder.build(sessionKey);
        digestCalc = dataEncryptor.getIntegrityCalculator();

        for (PGPKeyEncryptionMethodGenerator method : methods) {
            pOut.writePacket(method.generate(builder, sessionKey));
        }

        if (dataEncryptor instanceof PGPAEADDataEncryptor) {
            PGPAEADDataEncryptor aead = (PGPAEADDataEncryptor) dataEncryptor;
            AEADEncDataPacket aeadPacket = new AEADEncDataPacket(
                    defAlgorithm, aead.getAEADAlgorithm(), aead.getChunkSize(), aead.getIV());
            pOut = new BCPGOutputStream(out, PacketTags.AEAD_ENC_DATA, new byte[CHUNK_SIZE]);
            aeadPacket.encode(pOut);
            cOut = aead.getOutputStream(pOut);
            return new FilterOutputStream(cOut) {
                @Override
                public void close() throws IOException {
                    CustomEncryptedDataGenerator.this.close();
                    super.close();
                }
            };
        }

        pOut = new BCPGOutputStream(out, PacketTags.SYM_ENC_INTEGRITY_PRO, new byte[CHUNK_SIZE]);
        pOut.write(1);
        cOut = dataEncryptor.getOutputStream(pOut);
        genOut = new TeeOutputStream(digestCalc.getOutputStream(), cOut);

        byte[] prefix = new byte[dataEncryptor.getBlockSize() + 2];
        rand.nextBytes(prefix);
        prefix[prefix.length - 1] = prefix[prefix.length - 3];
        prefix[prefix.length - 2] = prefix[prefix.length - 4];
        genOut.write(prefix);

        return new FilterOutputStream(genOut) {
            @Override
            public void close() throws IOException {
                CustomEncryptedDataGenerator.this.close();
                super.close();
            }
        };
    }

    public void close() throws IOException {
        if (cOut != null) {
            if (digestCalc != null) {
                BCPGOutputStream mdOut = new BCPGOutputStream(genOut, PacketTags.MOD_DETECTION_CODE, 20L);
                mdOut.finish();
                mdOut.flush();
                byte[] digest = digestCalc.getDigest();
                cOut.write(digest);
            }
            cOut.close();
            cOut = null;
            pOut = null;
        }
    }
}
