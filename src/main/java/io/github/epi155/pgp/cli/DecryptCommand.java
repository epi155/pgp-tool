package io.github.epi155.pgp.cli;

import io.github.epi155.pgp.model.DecryptResult;
import io.github.epi155.pgp.model.PGPKeyInfo;
import io.github.epi155.pgp.service.PGPEngine;
import io.github.epi155.pgp.service.PassphraseRequiredException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DecryptCommand {

    private static final class SecretSpec {
        KeySelector.Source source;
        char[] pass;
    }

    private DecryptCommand() {}

    public static int run(Args args) throws Exception {
        if (args.flag("--help") || args.flag("-h")) {
            System.out.println(usage());
            return 0;
        }
        boolean quiet = false;
        boolean force = false;
        boolean decodeText = true;
        String input = null;
        String output = null;
        String outputDir = null;
        List<String> secretTokens = new ArrayList<>();
        List<String> verifyTokens = new ArrayList<>();
        List<String> passwordValues = new ArrayList<>();
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
                case "--output-dir":
                    outputDir = args.value("--output-dir");
                    break;
                case "--secret-key":
                    secretTokens.add(args.value("--secret-key"));
                    break;
                case "--verify-key":
                    verifyTokens.add(args.value("--verify-key"));
                    break;
                case "--password": {
                    String v = args.value("--password");
                    passwordValues.add(v);
                    break;
                }
                case "--password-file":
                    passwordValues.addAll(Io.readLinesFromFile(args.value("--password-file")));
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
                case "--text":
                    args.flag("--text");
                    decodeText = true;
                    break;
                case "--binary":
                    args.flag("--binary");
                    decodeText = false;
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
        if (output == null && outputDir == null) output = "-";

        byte[] cipher = Io.readAll(input);

        List<PGPSecretKey> secretKeys = new ArrayList<>();
        Map<Long, char[]> passByKeyId = new HashMap<>();
        Map<Long, String> secretKeyFile = new HashMap<>();
        for (String token : secretTokens) {
            SecretSpec spec = parseSecretToken(token, passFallback);
            for (PGPKeyInfo info : KeySelector.select(spec.source, true, false, false)) {
                secretKeys.add(info.getBcKey(PGPSecretKey.class));
                passByKeyId.put(info.getKeyId(), spec.pass);
                secretKeyFile.put(info.getKeyId(), spec.source.file.getPath());
            }
        }

        List<PGPPublicKey> verifyKeys = new ArrayList<>();
        Map<Long, String> verifyUid = new HashMap<>();
        for (String token : verifyTokens) {
            if (token.contains("#")) {
                throw new CliException("--verify-key takes a plain keyring path, not a #id filter "
                        + "(the signer key is resolved from the signature)", true);
            }
            KeySelector.Source source = new KeySelector.Source(new File(token), List.of());
            for (PGPKeyInfo info : KeySelector.select(source, false, false, false)) {
                verifyKeys.add(info.getBcKey(PGPPublicKey.class));
                if (info.getUserId() != null) verifyUid.put(info.getKeyId(), info.getUserId());
            }
        }

        List<char[]> pbePasswords = new ArrayList<>();
        for (String v : passwordValues) {
            if ("-".equals(v)) {
                pbePasswords.add(Io.readOneLineFromStdin().toCharArray());
            } else {
                pbePasswords.add(v.toCharArray());
            }
        }

        Path temp = Files.createTempFile("pgp-cli-decrypt-", ".bin");
        try {
            PGPEngine engine = new PGPEngine();
            engine.setPassphraseProvider(passByKeyId::get);
            for (Map.Entry<Long, char[]> e : passByKeyId.entrySet()) {
                engine.cachePassphrase(e.getKey(), e.getValue());
            }
            DecryptResult result = engine.decryptNestedToFile(cipher, temp, secretKeys, verifyKeys,
                    verifyUid, null, pbePasswords, null, decodeText);

            if (!quiet) {
                String meta = result.getMetadataText();
                if (meta != null && !meta.isEmpty()) System.err.println(meta);
                String verif = result.getVerificationMessage();
                if (verif != null && !verif.isEmpty()) System.err.println(verif);
            }

            boolean hasAttachments = result.getCompoundMessage() != null
                    && result.getCompoundMessage().hasAttachments();
            if (hasAttachments) {
                if (outputDir == null) {
                    throw new CliException("Message contains attachments: use --output-dir <dir> to save them", true);
                }
                Path dir = Path.of(outputDir);
                Files.createDirectories(dir);
                for (io.github.epi155.pgp.model.CompoundMessage.Attachment att
                        : result.getCompoundMessage().getAttachments()) {
                    String name = Path.of(att.getFilename()).getFileName().toString();
                    if (name.isEmpty() || ".".equals(name) || "..".equals(name)) continue;
                    Path target = dir.resolve(name);
                    att.saveTo(target);
                    if (!quiet) System.err.println("Attachment: " + target);
                }
                writeText(result.getCompoundMessage().getPlainText(), output, force);
            } else {
                writeFileOutput(temp, output, force);
            }

            if (result.getVerificationStatus() == DecryptResult.VerificationStatus.SIGNED_INVALID) {
                if (!quiet) System.err.println("pgp-tool: signature verification FAILED");
                return 1;
            }
            return 0;
        } catch (CliException e) {
            throw e;
        } catch (PassphraseRequiredException e) {
            throw new CliException(keyringLabel(secretKeyFile, e.getKeyId()) + e.getMessage());
        } catch (Exception e) {
            throw new CliException("Decryption failed: " + messageOf(e));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static SecretSpec parseSecretToken(String token, List<String> passFallback) throws CliException {
        SecretSpec spec = new SecretSpec();
        int colon = token.indexOf(':');
        String fileToken;
        if (colon >= 0) {
            fileToken = token.substring(0, colon);
            spec.pass = token.substring(colon + 1).toCharArray();
        } else {
            fileToken = token;
            spec.pass = passFallback.isEmpty() ? new char[0] : passFallback.remove(0).toCharArray();
        }
        spec.source = KeySelector.parseSource(fileToken, "secret key");
        return spec;
    }

    private static void writeFileOutput(Path src, String output, boolean force) throws CliException {
        if ("-".equals(output)) {
            try (InputStream in = Files.newInputStream(src)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) >= 0) {
                    System.out.write(buf, 0, n);
                }
                System.out.flush();
            } catch (IOException e) {
                throw new CliException("Failed to write output: " + e.getMessage());
            }
        } else {
            Path target = Path.of(output);
            if (!force && Files.exists(target)) {
                throw new CliException(output + ": file exists (use --force to overwrite)", true);
            }
            try {
                Files.copy(src, target, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                throw new CliException("Failed to write " + output + ": " + e.getMessage());
            }
        }
    }

    private static void writeText(String text, String output, boolean force) throws CliException {
        if (output == null) {
            System.out.println(text);
            return;
        }
        if ("-".equals(output)) {
            System.out.print(text);
            if (!text.endsWith("\n")) System.out.println();
            System.out.flush();
            return;
        }
        Path target = Path.of(output);
        if (!force && Files.exists(target)) {
            throw new CliException(output + ": file exists (use --force to overwrite)", true);
        }
        try {
            Files.writeString(target, text);
        } catch (IOException e) {
            throw new CliException("Failed to write " + output + ": " + e.getMessage());
        }
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
        return "Usage: pgp-tool -d, --decrypt [options] [input-file]\n"
                + "Decrypt an encrypted message (optionally nested) and verify signatures.\n\n"
                + "Options:\n"
                + "  -i, --input FILE        Encrypted input, or - for stdin (default stdin)\n"
                + "  -o, --output FILE       Output file, or - for stdout\n"
                + "  --output-dir DIR        Save message attachments into DIR\n"
                + "  --secret-key SPEC       Secret key: file[:passphrase], repeatable. The key to use\n"
                + "                            is chosen automatically from the message's recipient IDs;\n"
                + "                            #id is only needed when several keys in the same file have\n"
                + "                            different passphrases (e.g. file#0xID1:pass1 file#0xID2:pass2)\n"
                + "  --verify-key FILE       Public keyring for signature check, repeatable (the signer\n"
                + "                            is matched from the signature)\n"
                + "  --password PASSWORD     Password for a password layer, repeatable, in decrypt\n"
                + "                            order (outermost layer first); - reads one line from stdin\n"
                + "  --password-file FILE    Read passwords (one per line) from FILE (or - for stdin)\n"
                + "  --passphrase P          Fallback secret-key passphrase (or - for stdin)\n"
                + "  --passphrase-file FILE  Fallback passphrases, one per line\n"
                + "  --text / --binary       Treat output as text (default text)\n"
                + "  --force                 Overwrite the output file if it exists\n"
                + "  --quiet                 Suppress the metadata / signature output\n"
                + "\nExit status is 1 if a signature fails verification.\n";
    }
}
