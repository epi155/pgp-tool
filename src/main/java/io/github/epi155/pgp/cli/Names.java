package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.service.AsconTags;
import io.github.epi155.pgp.service.CustomAlgorithms;
import io.github.epi155.pgp.service.CustomCompression;
import io.github.epi155.pgp.service.SerpentTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

import java.util.Locale;

public final class Names {

    private Names() {}

    public static int symmetric(String name) throws CliException {
        switch (name.toUpperCase(Locale.ROOT)) {
            case "AES-128": return SymmetricKeyAlgorithmTags.AES_128;
            case "AES-192": return SymmetricKeyAlgorithmTags.AES_192;
            case "AES-256": return SymmetricKeyAlgorithmTags.AES_256;
            case "CAST5": return SymmetricKeyAlgorithmTags.CAST5;
            case "BLOWFISH": return SymmetricKeyAlgorithmTags.BLOWFISH;
            case "TRIPLE-DES":
            case "3DES": return SymmetricKeyAlgorithmTags.TRIPLE_DES;
            case "TWOFISH": return SymmetricKeyAlgorithmTags.TWOFISH;
            case "CAMELLIA-128": return SymmetricKeyAlgorithmTags.CAMELLIA_128;
            case "CAMELLIA-192": return SymmetricKeyAlgorithmTags.CAMELLIA_192;
            case "CAMELLIA-256": return SymmetricKeyAlgorithmTags.CAMELLIA_256;
            case "SERPENT-128": return SerpentTags.SERPENT_128;
            case "SERPENT-192": return SerpentTags.SERPENT_192;
            case "SERPENT-256": return SerpentTags.SERPENT_256;
            case "CHACHA20":
            case "CHACHA20-POLY1305": return CustomAlgorithms.CHACHA20_POLY1305;
            case "ASCON":
            case "ASCON-128": return AsconTags.ASCON_128;
            default:
                throw new CliException("Unknown symmetric algorithm: '" + name
                        + "' (use AES-128/192/256, CAST5, Blowfish, Triple-DES, Twofish, "
                        + "Camellia-128/192/256, Serpent-128/192/256, ChaCha20-Poly1305, ASCON)", true);
        }
    }

    public static int hash(String name) throws CliException {
        switch (name.toUpperCase(Locale.ROOT)) {
            case "SHA-256":
            case "SHA256": return HashAlgorithmTags.SHA256;
            case "SHA-384":
            case "SHA384": return HashAlgorithmTags.SHA384;
            case "SHA-512":
            case "SHA512": return HashAlgorithmTags.SHA512;
            case "SHA3-256": return HashAlgorithmTags.SHA3_256;
            case "SHA3-512": return HashAlgorithmTags.SHA3_512;
            default:
                throw new CliException("Unknown hash algorithm: '" + name
                        + "' (use SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512)", true);
        }
    }

    public static boolean isHash(String name) {
        try {
            hash(name);
            return true;
        } catch (CliException e) {
            return false;
        }
    }

    public static int compression(String name) throws CliException {
        switch (name.toUpperCase(Locale.ROOT)) {
            case "UNCOMPRESSED":
            case "NONE":
            case "0": return CompressionAlgorithmTags.UNCOMPRESSED;
            case "ZIP": return CompressionAlgorithmTags.ZIP;
            case "ZLIB": return CompressionAlgorithmTags.ZLIB;
            case "BZIP2": return CompressionAlgorithmTags.BZIP2;
            case "XZ": return CustomCompression.XZ;
            case "ZSTD": return CustomCompression.ZSTD;
            default:
                throw new CliException("Unknown compression algorithm: '" + name
                        + "' (use ZIP, ZLIB, BZIP2, XZ, ZSTD, UNCOMPRESSED)", true);
        }
    }
}
