package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.model.CompoundCodec;
import io.github.epi155.pgp.model.CompoundMessage;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.PGPEngine;
import io.github.epi155.pgp.service.PassphraseRequiredException;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class EncryptCommand {

    private static final class Layer {
        boolean isPass;
        List<PGPPublicKey> encKeys;
        char[] password;
        int symAlgo;
    }

    private static final class SignSpec {
        KeySelector.Source source;
        char[] pass;
        int hash;
    }

    private EncryptCommand() {}

    public static int run(Args args) throws Exception {
        if (args.flag("--help")) {
            System.out.println(usage());
            return 0;
        }
        boolean quiet = false;
        boolean force = false;
        boolean armor = true;
        String input = null;
        String output = null;
        int compress = CompressionAlgorithmTags.ZLIB;
        List<String> layerTokens = new ArrayList<>();
        List<String> passwordValues = new ArrayList<>();
        List<String> signTokens = new ArrayList<>();
        List<String> attachFiles = new ArrayList<>();
        List<String> passFallback = new ArrayList<>();

        while (args.hasNext()) {
            String tok = args.peek();
            switch (tok) {
                case "--input":
                case "-i":
                    input = args.value(tok);
                    break;
                case "--output":
                case "-o":
                    output = args.value(tok);
                    break;
                case "--layer":
                    layerTokens.add(args.value("--layer"));
                    break;
                case "--password": {
                    String v = args.value("--password");
                    passwordValues.add(v);
                    break;
                }
                case "--password-file":
                    passwordValues.addAll(Io.readLinesFromFile(args.value("--password-file")));
                    break;
                case "--sign-key":
                    signTokens.add(args.value("--sign-key"));
                    break;
                case "--passphrase": {
                    String v = args.value("--passphrase");
                    if ("-".equals(v)) v = Io.readOneLineFromStdin();
                    passFallback.add(v);
                    break;
                }
                case "--passphrase-file":
                    passFallback.addAll(Io.readLinesFromFile(args.value("--passphrase-file")));
                    break;
                case "--attach":
                    attachFiles.add(args.value("--attach"));
                    break;
                case "--compress":
                    compress = Names.compression(args.value("--compress"));
                    break;
                case "--armor":
                    args.flag("--armor");
                    armor = true;
                    break;
                case "--no-armor":
                    args.flag("--no-armor");
                    armor = false;
                    break;
                case "--force":
                    args.flag("--force");
                    force = true;
                    break;
                case "--quiet":
                    args.flag("--quiet");
                    quiet = true;
                    break;
                default:
                    if (tok.startsWith("--") || (tok.startsWith("-") && tok.length() > 1)) {
                        throw new CliException("Unknown option: " + tok, true);
                    }
                    args.next();
                    if (input == null) {
                        input = tok;
                    } else {
                        throw new CliException("Unexpected extra argument: " + tok, true);
                    }
            }
        }
        if (input == null) input = "-";
        if (output == null) output = "-";

        byte[] data = Io.readAll(input);
        String fileName;
        if (!attachFiles.isEmpty()) {
            String text = new String(data, StandardCharsets.UTF_8);
            if (text.isEmpty() && attachFiles.size() == 1) {
                fileName = Path.of(attachFiles.get(0)).getFileName().toString();
                data = Io.readAll(attachFiles.get(0));
            } else {
                List<CompoundMessage.Attachment> attachments = new ArrayList<>();
                for (String f : attachFiles) {
                    Path p = Path.of(f);
                    if (!Files.isRegularFile(p)) {
                        throw new CliException(f + ": no such file", true);
                    }
                    attachments.add(new CompoundMessage.Attachment(
                            p.getFileName().toString(), Files.readAllBytes(p)));
                }
                fileName = "_CONSOLE";
                data = CompoundCodec.encode(new CompoundMessage(text, attachments));
            }
        } else {
            fileName = "-".equals(input) ? "_CONSOLE" : Path.of(input).getFileName().toString();
        }

        List<char[]> passwordPool = new ArrayList<>();
        for (String v : passwordValues) {
            if ("-".equals(v)) {
                passwordPool.add(Io.readOneLineFromStdin().toCharArray());
            } else {
                passwordPool.add(v.toCharArray());
            }
        }

        List<SignSpec> signSpecs = new ArrayList<>();
        for (String token : signTokens) {
            signSpecs.add(parseSignToken(token, passFallback));
        }

        List<PGPSecretKey> signKeys = new ArrayList<>();
        List<char[]> signPassphrases = new ArrayList<>();
        List<Integer> hashAlgos = new ArrayList<>();
        Map<Long, String> signKeyFile = new HashMap<>();
        for (SignSpec spec : signSpecs) {
            for (PGPKeyInfo info : KeySelector.select(spec.source, true, false, true)) {
                signKeys.add(info.getBcKey(PGPSecretKey.class));
                signPassphrases.add(spec.pass);
                hashAlgos.add(spec.hash);
                signKeyFile.put(info.getKeyId(), spec.source.file.getPath());
            }
        }

        List<Layer> layers = new ArrayList<>();
        int passIndex = 0;
        for (String token : layerTokens) {
            Layer layer = parseLayer(token);
            if (layer.isPass) {
                if (passIndex >= passwordPool.size()) {
                    throw new CliException("Not enough passwords for PASS layers (provided "
                            + passwordPool.size() + ", needed " + (passIndex + 1) + ")", true);
                }
                layer.password = passwordPool.get(passIndex++);
            }
            layers.add(layer);
        }
        int unused = passwordPool.size() - passIndex;
        if (unused > 0 && !quiet) {
            System.err.println("pgp-tool: warning: " + unused + " unused password(s)");
        }

        if (!"-".equals(output) && !force && Files.exists(Path.of(output))) {
            throw new CliException(output + ": file exists (use --force to overwrite)", true);
        }

        byte[] result;
        try {
            PGPEngine engine = new PGPEngine();
            if (layers.isEmpty()) {
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                engine.encryptCompress(data, fileName, bOut,
                        signKeys, signPassphrases, compress, hashAlgos, armor, null);
                result = bOut.toByteArray();
            } else {
                byte[] enc = data;
                for (int i = 0; i < layers.size(); i++) {
                    Layer layer = layers.get(i);
                    boolean last = (i == layers.size() - 1);
                    boolean arm = last && armor;
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    if (i == 0) {
                        if (layer.isPass) {
                            engine.encryptPassword(enc, fileName, bOut, layer.password,
                                    signKeys, signPassphrases, layer.symAlgo, compress, hashAlgos, arm, null);
                        } else {
                            engine.encrypt(enc, fileName, bOut, layer.encKeys,
                                    signKeys, signPassphrases, layer.symAlgo, compress, hashAlgos, arm, null);
                        }
                    } else {
                        if (layer.isPass) {
                            engine.encryptRawPassword(enc, bOut, layer.password, layer.symAlgo, arm, null);
                        } else {
                            engine.encryptRaw(enc, bOut, layer.encKeys, layer.symAlgo, arm, null);
                        }
                    }
                    enc = bOut.toByteArray();
                }
                result = enc;
            }
        } catch (CliException e) {
            throw e;
        } catch (PassphraseRequiredException e) {
            throw new CliException(keyringLabel(signKeyFile, e.getKeyId()) + e.getMessage());
        } catch (Exception e) {
            throw new CliException("Encryption failed: " + messageOf(e));
        }

        if ("-".equals(output)) {
            try {
                System.out.write(result);
                System.out.flush();
            } catch (Exception e) {
                throw new CliException("Failed to write output: " + e.getMessage());
            }
        } else {
            try {
                Files.write(Path.of(output), result);
            } catch (Exception e) {
                throw new CliException("Failed to write " + output + ": " + e.getMessage());
            }
        }
        return 0;
    }

    private static Layer parseLayer(String token) throws CliException {
        int colon = token.indexOf(':');
        if (colon <= 0) {
            throw new CliException("Invalid --layer '" + token
                    + "' (expected KEY:file[#id][;file2[#id]]:ALGO or PASS:ALGO)", true);
        }
        String kind = token.substring(0, colon).toUpperCase(Locale.ROOT);
        String rest = token.substring(colon + 1);
        Layer layer = new Layer();
        if (kind.equals("PASS")) {
            layer.isPass = true;
            layer.symAlgo = Names.symmetric(rest);
            return layer;
        }
        if (kind.equals("KEY")) {
            int lastColon = rest.lastIndexOf(':');
            if (lastColon <= 0) {
                throw new CliException("Invalid --layer '" + token
                        + "' (expected KEY:file[#id][;file2[#id]]:ALGO)", true);
            }
            layer.isPass = false;
            layer.symAlgo = Names.symmetric(rest.substring(lastColon + 1));
            List<PGPPublicKey> keys = new ArrayList<>();
            Set<Long> seen = new HashSet<>();
            for (String source : rest.substring(0, lastColon).split(";")) {
                if (source.trim().isEmpty()) {
                    throw new CliException("Empty recipient source in --layer '" + token + "'", true);
                }
                for (PGPPublicKey key : KeySelector.publicKeys(source.trim(), true)) {
                    if (seen.add(key.getKeyID())) keys.add(key);
                }
            }
            if (keys.isEmpty()) {
                throw new CliException("No recipients resolved for --layer '" + token + "'", true);
            }
            layer.encKeys = keys;
            return layer;
        }
        throw new CliException("Invalid --layer kind '" + kind + "' (use KEY or PASS)", true);
    }

    private static SignSpec parseSignToken(String token, List<String> passFallback) throws CliException {
        SignSpec spec = new SignSpec();
        String body = token;
        String hashName = "SHA-256";
        int lastColon = token.lastIndexOf(':');
        if (lastColon >= 0 && Names.isHash(token.substring(lastColon + 1))) {
            hashName = token.substring(lastColon + 1);
            body = token.substring(0, lastColon);
        }
        spec.hash = Names.hash(hashName);
        int firstColon = body.indexOf(':');
        String fileToken;
        if (firstColon >= 0) {
            fileToken = body.substring(0, firstColon);
            spec.pass = body.substring(firstColon + 1).toCharArray();
        } else {
            fileToken = body;
            spec.pass = passFallback.isEmpty() ? new char[0] : passFallback.remove(0).toCharArray();
        }
        spec.source = KeySelector.parseSource(fileToken, "sign key");
        return spec;
    }

    private static String messageOf(Throwable t) {
        Throwable c = t.getCause() != null ? t.getCause() : t;
        String m = c.getMessage();
        return m != null && !m.isEmpty() ? m : c.getClass().getSimpleName();
    }

    private static String keyringLabel(Map<Long, String> keyFile, long keyId) {
        String file = keyFile.get(keyId);
        return file != null ? file + ": " : "";
    }

    static String usage() {
        return "Usage: pgp-tool --encrypt [options] [input-file]\n"
                + "Encrypt data to one or more recipients / password layers (inner to outer).\n\n"
                + "Options:\n"
                + "  -i, --input FILE        Input file, or - for stdin (default stdin)\n"
                + "  -o, --output FILE       Output file, or - for stdout (default stdout)\n"
                + "  --layer TOKEN           Encryption layer, repeatable, inner to outer:\n"
                + "                            KEY:file[#id][;file[#id]]...:ALGO\n"
                + "                            PASS:ALGO\n"
                + "                            With no #id every encryption-capable key in the\n"
                + "                            keyring is used; #id selects exactly one (short\n"
                + "                            0xABCDEF12, full 16-hex, or 32-hex fingerprint).\n"
                 + "                            ALGO: AES-128/192/256, CAST5, Blowfish, Triple-DES,\n"
                 + "                            Twofish, Camellia-128/192/256, Serpent-128/192/256,\n"
                 + "                            ChaCha20-Poly1305\n"
                + "  --password PASSWORD     Password for a PASS layer, repeatable (one per layer,\n"
                + "                            or - to read one line from stdin)\n"
                + "  --password-file FILE    Read passwords (one per line) from FILE (or - for stdin)\n"
                + "  --sign-key SPEC         Sign with a key: file[#id][:passphrase[:HASH]]\n"
                + "                            HASH: SHA-256 (default), SHA-384, SHA-512, RIPEMD160\n"
                + "  --passphrase P          Fallback signing passphrase (or - for stdin)\n"
                + "  --passphrase-file FILE  Fallback signing passphrases, one per line\n"
                + "  --compress ALGO         ZIP, ZLIB, BZIP2, XZ, ZSTD, UNCOMPRESSED (default ZLIB)\n"
                + "  --attach FILE           Attach FILE (repeatable) in a compound message\n"
                + "  --armor / --no-armor    ASCII armor the output (default armor)\n"
                + "  --force                 Overwrite the output file if it exists\n"
                + "  --quiet                 Suppress warnings\n";
    }
}
