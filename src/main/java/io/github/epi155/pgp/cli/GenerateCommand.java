package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.model.GeneratedKey;
import io.github.epi155.pgp.model.KeyConfig;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.KeyGeneratorService;
import io.github.epi155.pgp.service.KeyringLoader;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class GenerateCommand {

    private static final Set<String> KNOWN_CURVES = Set.of(
            "secp256r1", "secp384r1", "secp521r1",
            "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1");

    private GenerateCommand() {}

    public static int run(Args args, boolean curve448Enabled) throws Exception {
        if (args.flag("--help") || args.flag("-h")) {
            System.out.println(usage());
            return 0;
        }
        boolean quiet = false;
        String userId = null;
        String masterSpec = "RSA-3072";
        boolean masterEncrypt = false;
        long expiration = 0;
        String passphrase = null;
        String outputDir = null;
        List<String> subSpecs = new ArrayList<>();

        while (args.hasNext()) {
            String tok = args.peek();
            switch (tok) {
                case "--user-id": userId = args.value("--user-id"); break;
                case "--master": masterSpec = args.value("--master"); break;
                case "--master-encrypt": args.flag("--master-encrypt"); masterEncrypt = true; break;
                case "--expiration": expiration = parseLong(args.value("--expiration"), "--expiration"); break;
                case "--subkey": subSpecs.add(args.value("--subkey")); break;
                case "--passphrase": passphrase = args.value("--passphrase"); break;
                case "--passphrase-file":
                    passphrase = readPassphraseFile(args.value("--passphrase-file"));
                    break;
                case "--output": outputDir = args.value("--output"); break;
                case "--quiet": args.flag("--quiet"); quiet = true; break;
                default:
                    throw new CliException("Unknown option: " + tok, true);
            }
        }

        if (userId == null || userId.isEmpty()) {
            throw new CliException("--user-id is required (e.g. \"Name <email@example.com>\")", true);
        }
        if (outputDir == null) {
            throw new CliException("--output <dir> is required", true);
        }

        KeyConfig.KeySpec master = parseSpec(masterSpec, true, curve448Enabled);
        if (masterEncrypt) {
            if (master.getAlgorithm() != KeyConfig.KeySpec.Algorithm.RSA) {
                throw new CliException("--master-encrypt is only valid for an RSA master key", true);
            }
            master.setCanEncrypt(true);
        }
        master.setExpirationSeconds(expiration);

        KeyConfig config = new KeyConfig();
        config.setUserId(userId);
        config.setMasterKey(master);
        for (String s : subSpecs) {
            config.getSubKeys().add(parseSpec(s, false, curve448Enabled));
        }

        try {
            GeneratedKey generated = KeyGeneratorService.generate(config);
            PGPSecretKeyRing secRing = generated.getSecretKeyRing();
            if (passphrase != null && !passphrase.isEmpty()) {
                secRing = KeyGeneratorService.reEncrypt(secRing, passphrase.toCharArray());
            }

            Path dir = Path.of(outputDir);
            Files.createDirectories(dir);
            String name = suggestedName(userId);
            Path pubPath = dir.resolve(name + "-public.asc");
            Path secPath = dir.resolve(name + "-secret.asc");

            try (ArmoredOutputStream out = new ArmoredOutputStream(Files.newOutputStream(pubPath))) {
                generated.getPublicKeyRing().encode(out);
            }
            try (ArmoredOutputStream out = new ArmoredOutputStream(Files.newOutputStream(secPath))) {
                secRing.encode(out);
            }

            if (!quiet) {
                System.out.println("Public key : " + pubPath);
                System.out.println("Secret key : " + secPath);
                for (PGPKeyInfo info : KeyringLoader.extractKeyInfos(generated.getPublicKeyRing())) {
                    System.out.println("  " + info);
                    for (PGPKeyInfo sub : info.getSubKeys()) {
                        System.out.println("     \\- " + sub);
                    }
                }
                System.out.println("Secret key passphrase: " + (passphrase == null || passphrase.isEmpty()
                        ? "none" : "set"));
            }
            return 0;
        } catch (CliException e) {
            throw e;
        } catch (Exception e) {
            throw new CliException("Key generation failed: " + e.getMessage());
        }
    }

    private static String readPassphraseFile(String name) throws CliException {
        List<String> lines = Io.readLinesFromFile(name);
        return lines.isEmpty() ? "" : lines.get(0);
    }

    private static long parseLong(String value, String flag) throws CliException {
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new CliException(flag + ": invalid number '" + value + "'", true);
        }
    }

    private static KeyConfig.KeySpec parseSpec(String token, boolean isMaster, boolean curve448Enabled) throws CliException {
        String[] parts = token.split(":", -1);
        if (parts.length > 3) {
            throw new CliException("Invalid key spec '" + token + "' (expected ALGO[:FLAGS[:EXP]])", true);
        }
        String algoToken = parts[0].trim();
        String flagsToken = parts.length >= 2 ? parts[1].trim() : "";
        long exp = parts.length >= 3 ? parseLong(parts[2].trim(), "key spec") : 0;

        KeyConfig.KeySpec spec = new KeyConfig.KeySpec();
        String algo = algoToken.toUpperCase(Locale.ROOT);
        if (algo.startsWith("RSA-")) {
            int size;
            try {
                size = Integer.parseInt(algo.substring(4));
            } catch (NumberFormatException e) {
                throw new CliException("Invalid RSA size in '" + algoToken + "'", true);
            }
            if (size != 2048 && size != 3072 && size != 4096) {
                throw new CliException("RSA size must be 2048, 3072 or 4096", true);
            }
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.RSA);
            spec.setRsaSize(size);
        } else if (algo.startsWith("EC-")) {
            String curve = algoToken.substring(3);
            if (!KNOWN_CURVES.contains(curve)) {
                throw new CliException("Unknown EC curve '" + curve + "' (use secp256r1, secp384r1, "
                        + "secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1)", true);
            }
            spec.setAlgorithm(isMaster ? KeyConfig.KeySpec.Algorithm.ECDSA : KeyConfig.KeySpec.Algorithm.ECDH);
            spec.setEcCurve(curve);
        } else if (algo.equals("ED25519")) {
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.EDDSA);
        } else if (algo.equals("ED448")) {
            if (!curve448Enabled) {
                throw new CliException("Ed448 keys are not supported by gpg yet; requires --curve448", true);
            }
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ED448);
        } else if (algo.equals("X25519")) {
            if (isMaster) throw new CliException("X25519 cannot be used as a master key", true);
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.XDH);
        } else if (algo.equals("X448")) {
            if (isMaster) throw new CliException("X448 cannot be used as a master key", true);
            if (!curve448Enabled) {
                throw new CliException("X448 keys are not supported by gpg yet; requires --curve448", true);
            }
            spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.X448);
        } else {
            throw new CliException("Unknown algorithm '" + algoToken + "'", true);
        }

        boolean flagsGiven = !flagsToken.isEmpty();
        boolean canCertify;
        boolean canSign;
        boolean canEncrypt;
        boolean canAuthenticate;
        if (flagsGiven) {
            List<String> flags = Arrays.asList(flagsToken.split(","));
            for (String f : flags) {
                if (!f.equals("sign") && !f.equals("encrypt") && !f.equals("certify") && !f.equals("authenticate")) {
                    throw new CliException("Invalid key flag '" + f + "' (use sign, encrypt, certify, authenticate)", true);
                }
            }
            canCertify = flags.contains("certify");
            canSign = flags.contains("sign");
            canEncrypt = flags.contains("encrypt");
            canAuthenticate = flags.contains("authenticate");
        } else {
            boolean xdh = spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.XDH
                    || spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.X448;
            boolean ed = spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.EDDSA
                    || spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.ED448;
            canCertify = isMaster;
            canSign = isMaster || !xdh;
            canEncrypt = !isMaster && !ed;
            canAuthenticate = false;
        }

        if (isMaster && spec.getAlgorithm() != KeyConfig.KeySpec.Algorithm.RSA) {
            canEncrypt = false;
        }
        if (spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.EDDSA
                || spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.ED448) {
            if (canEncrypt) {
                throw new CliException("Ed25519/Ed448 keys cannot encrypt", true);
            }
            canEncrypt = false;
        }
        if (spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.XDH
                || spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.X448) {
            if (canSign) {
                throw new CliException("X25519/X448 keys cannot sign", true);
            }
            canSign = false;
            if (canAuthenticate) {
                throw new CliException("X25519/X448 keys cannot authenticate", true);
            }
            canAuthenticate = false;
        }
        if (!isMaster && spec.getAlgorithm() == KeyConfig.KeySpec.Algorithm.ECDH) {
            if ((canSign || canAuthenticate) && !canEncrypt) {
                spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ECDSA);
            } else {
                spec.setAlgorithm(KeyConfig.KeySpec.Algorithm.ECDH);
            }
        }

        spec.setCanCertify(canCertify);
        spec.setCanSign(canSign);
        spec.setCanEncrypt(canEncrypt);
        spec.setCanAuthenticate(canAuthenticate);
        spec.setExpirationSeconds(exp);
        return spec;
    }

    private static String suggestedName(String userId) {
        int at = userId.indexOf('<');
        int close = userId.lastIndexOf('>');
        String name;
        if (at >= 0 && close > at) {
            name = userId.substring(at + 1, close).trim();
            int a2 = name.indexOf('@');
            if (a2 > 0) name = name.substring(0, a2);
        } else {
            name = userId;
        }
        name = name.replaceAll("[\\\\/:*?\"<>| ]", "_");
        return name.isEmpty() ? "key" : name;
    }

    static String usage() {
        return "Usage: pgp-tool -g, --generate --user-id \"Name <email>\" [options]\n"
                + "Generate a new PGP key pair (armored .asc files) into the output directory.\n\n"
                + "Options:\n"
                + "  --user-id UID            Identity, e.g. \"Alice <alice@example.com>\" (required)\n"
                + "  --master SPEC            Master key spec (default RSA-3072)\n"
                + "  --master-encrypt         Also allow the RSA master to encrypt\n"
                 + "  --subkey SPEC            Subkey spec, repeatable:\n"
                 + "                             RSA-2048|RSA-3072|RSA-4096 | EC-secp256r1\n"
                 + "                             EC-secp384r1 | EC-secp521r1 | EC-brainpoolP256r1\n"
                 + "                             EC-brainpoolP384r1 | EC-brainpoolP512r1 | Ed25519\n"
                 + "                             Ed448 | X25519 | X448\n"
                 + "                             (Ed448/X448 need --curve448; not yet\n"
                 + "                             supported by gpg)\n"
                 + "                             optional [:sign,encrypt,certify,authenticate]\n"
                 + "                             optional [:EXP_SECONDS]\n"
                 + "  --expiration SECONDS     Master key expiration (default never)\n"
                 + "  --passphrase PASS        Protect the secret key with PASS\n"
                + "  --passphrase-file FILE   Read the passphrase from FILE (or - for stdin)\n"
                 + "  --output DIR             Write <name>-public.asc and <name>-secret.asc\n"
                 + "                             into DIR (required)\n"
                + "  --quiet                  Suppress the summary output\n";
    }
}
